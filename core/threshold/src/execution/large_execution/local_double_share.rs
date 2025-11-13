use super::{
    coinflip::{Coinflip, SecureCoinflip},
    constants::DISPUTE_STAT_SEC,
    local_single_share::{
        compute_check_values, look_for_disputes, verify_sender_challenge, MapsSharesChallenges,
    },
    share_dispute::{SecureShareDispute, ShareDispute, ShareDisputeOutputDouble},
};
use crate::execution::{
    communication::broadcast::{Broadcast, SyncReliableBroadcast},
    runtime::sessions::large_session::LargeSessionHandles,
};
use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingWithExceptionalSequence},
    error::error_handler::anyhow_error_and_log,
    execution::runtime::party::Role,
    networking::value::BroadcastValue,
    ProtocolDescription,
};
use async_trait::async_trait;
use itertools::Itertools;
use num_integer::div_ceil;
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::instrument;

pub(crate) const LOCAL_DOUBLE_MAX_ITER: usize = 30;

pub type SecureLocalDoubleShare =
    RealLocalDoubleShare<SecureCoinflip, SecureShareDispute, SyncReliableBroadcast>;

pub struct DoubleShares<Z> {
    pub(crate) share_t: Vec<Z>,
    pub(crate) share_2t: Vec<Z>,
}

#[async_trait]
pub trait LocalDoubleShare: ProtocolDescription + Send + Sync + Clone {
    async fn execute<Z: Derive + ErrorCorrect + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, DoubleShares<Z>>>;
}

pub(crate) type MapsDoubleSharesChallenges<Z> = (
    BTreeMap<Role, Z>,
    BTreeMap<Role, Z>,
    BTreeMap<Role, Z>,
    BTreeMap<Role, Z>,
);

#[derive(Default, Clone)]
pub struct RealLocalDoubleShare<C: Coinflip, S: ShareDispute, BCast: Broadcast> {
    coinflip: C,
    share_dispute: S,
    broadcast: BCast,
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> ProtocolDescription
    for RealLocalDoubleShare<C, S, BCast>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-RealLocalDoubleShare:\n{}\n{}\n{}",
            indent,
            C::protocol_desc(depth + 1),
            S::protocol_desc(depth + 1),
            BCast::protocol_desc(depth + 1)
        )
    }
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> RealLocalDoubleShare<C, S, BCast> {
    pub fn new(coinflip_strategy: C, share_dispute_strategy: S, broadcast_strategy: BCast) -> Self {
        RealLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        }
    }
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> LocalDoubleShare
    for RealLocalDoubleShare<C, S, BCast>
{
    #[instrument(name="LocalDoubleShare",skip(self,session,secrets),fields(sid = ?session.session_id(),my_role=?session.my_role(),batch_size=?secrets.len()))]
    async fn execute<Z: Derive + ErrorCorrect + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, DoubleShares<Z>>> {
        if secrets.is_empty() {
            return Err(anyhow_error_and_log(
                "Passed an empty secrets vector to LocalDoubleShare",
            ));
        }
        //Keeps executing til verification passes
        for _ in 0..LOCAL_DOUBLE_MAX_ITER {
            let mut shared_secrets_double;
            let mut x;
            let mut shared_pads_double;

            loop {
                let corrupt_start = session.corrupt_roles().clone();

                //ShareDispute will fill shares from disputed parties with 0s
                shared_secrets_double = self.share_dispute.execute_double(session, secrets).await?;

                shared_pads_double = send_receive_pads_double(session, &self.share_dispute).await?;

                x = self.coinflip.execute(session).await?;

                // if the corrupt roles have not changed, we can exit the loop and move on, otherwise start from the top
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }

            if verify_sharing(
                session,
                &mut shared_secrets_double,
                &shared_pads_double,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                return format_output(shared_secrets_double);
            }
        }
        Err(anyhow_error_and_log(
            "Failed to verify sharing after {LOCAL_DOUBLE_MAX_ITER} iterations for `RealLocalDoubleShare`",
        ))
    }
}

//Format the double sharing correctly for output
pub(crate) fn format_output<Z>(
    shared_secrets_double: ShareDisputeOutputDouble<Z>,
) -> anyhow::Result<HashMap<Role, DoubleShares<Z>>> {
    let (output_t, mut output_2t) = (
        shared_secrets_double.output_t.all_shares,
        shared_secrets_double.output_2t.all_shares,
    );
    let result: HashMap<Role, DoubleShares<Z>> = output_t
        .into_iter()
        .map(|(role_pi, output_t_pi)| {
            if let Some(output_2t_pi) = output_2t.remove(&role_pi) {
                Ok((
                    role_pi,
                    DoubleShares {
                        share_t: output_t_pi,
                        share_2t: output_2t_pi,
                    },
                ))
            } else {
                //This should never happen as ShareDispute fills all missing values with default 0
                Err(anyhow_error_and_log(format!(
                    "Missing 2t share from party {role_pi}"
                )))
            }
        })
        .try_collect()?;
    Ok(result)
}

pub(crate) async fn send_receive_pads_double<Z, L, S>(
    session: &mut L,
    share_dispute: &S,
) -> anyhow::Result<ShareDisputeOutputDouble<Z>>
where
    Z: RingWithExceptionalSequence + Derive + Invert,
    L: LargeSessionHandles,
    S: ShareDispute,
{
    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let my_pads = (0..m).map(|_| Z::sample(session.rng())).collect_vec();
    share_dispute.execute_double(session, &my_pads).await
}

pub(crate) async fn verify_sharing<
    Z: Ring + Derive + ErrorCorrect,
    L: LargeSessionHandles,
    BCast: Broadcast,
>(
    session: &mut L,
    secrets_double: &mut ShareDisputeOutputDouble<Z>,
    pads_double: &ShareDisputeOutputDouble<Z>,
    x: &Z,
    l: usize,
    broadcast: &BCast,
) -> anyhow::Result<bool> {
    //Unpacking shares
    let (secrets_shares_all_t, my_shared_secrets_t) = (
        &mut secrets_double.output_t.all_shares,
        &mut secrets_double.output_t.shares_own_secret,
    );
    let (secrets_shares_all_2t, my_shared_secrets_2t) = (
        &mut secrets_double.output_2t.all_shares,
        &mut secrets_double.output_2t.shares_own_secret,
    );

    let (pads_shares_all_t, my_share_pads_t) = (
        &pads_double.output_t.all_shares,
        &pads_double.output_t.shares_own_secret,
    );
    let (pads_shares_all_2t, my_share_pads_2t) = (
        &pads_double.output_2t.all_shares,
        &pads_double.output_2t.shares_own_secret,
    );

    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let my_role = session.my_role();

    //TODO: Could be done in parallel (to minimize round complexity)
    for g in 0..m {
        let map_challenges =
            Z::derive_challenges_from_coinflip(x, g.try_into()?, l, session.roles());

        //Compute my share of check values for every sharing of degree t
        let map_share_check_values_t = compute_check_values(
            pads_shares_all_t,
            &map_challenges,
            secrets_shares_all_t,
            g,
            None,
        )?;

        //Compute my share of check values for every sharing of degree 2t
        let map_share_check_values_2t = compute_check_values(
            pads_shares_all_2t,
            &map_challenges,
            secrets_shares_all_2t,
            g,
            None,
        )?;

        //Compute the shares of the check values for every sharing of degree t where I am sender
        let map_share_my_check_values_t = compute_check_values(
            my_share_pads_t,
            &map_challenges,
            my_shared_secrets_t,
            g,
            Some(&my_role),
        )?;

        //Compute the shares of the check values for every sharing of degree 2t where I am sender
        let map_share_my_check_values_2t = compute_check_values(
            my_share_pads_2t,
            &map_challenges,
            my_shared_secrets_2t,
            g,
            Some(&my_role),
        )?;

        let corrupt_before_bc = session.corrupt_roles().clone();

        //Broadcast:
        // - my share of check values on all sharing of degree t and 2t
        // - the shares of all the parties on sharing of degree t and 2t wher I am sender
        let bcast_data = broadcast
            .broadcast_from_all_w_corrupt_set_update(
                session,
                BroadcastValue::LocalDoubleShare((
                    map_share_check_values_t,
                    map_share_check_values_2t,
                    map_share_my_check_values_t,
                    map_share_my_check_values_2t,
                )),
            )
            .await?;

        // If the corrupt roles have not changed, we can continue, otherwise start from beginning
        if *session.corrupt_roles() != corrupt_before_bc {
            return Ok(false);
        }

        //Split Broadcast data into degree t and 2t, allowing to mimic behaviour of local single sharing
        let mut bcast_data_t = HashMap::<Role, MapsSharesChallenges<Z>>::new();
        let mut bcast_data_2t = HashMap::<Role, MapsSharesChallenges<Z>>::new();
        let mut bcast_corrupts = HashSet::<Role>::new();
        for (role, map_data) in bcast_data.into_iter() {
            if let BroadcastValue::LocalDoubleShare((
                data_share_t,
                data_share_2t,
                data_check_t,
                data_check_2t,
            )) = map_data
            {
                bcast_data_t.insert(
                    role,
                    MapsSharesChallenges {
                        checks_for_all: data_share_t,
                        checks_for_mine: data_check_t,
                    },
                );
                bcast_data_2t.insert(
                    role,
                    MapsSharesChallenges {
                        checks_for_all: data_share_2t,
                        checks_for_mine: data_check_2t,
                    },
                );
            } else {
                //Otherwise, wrong type from sender, mark it corrupt
                tracing::warn!(
                    "Received wrong type from {role} in broadcast, marking it as corrupt"
                );
                bcast_corrupts.insert(role);
            }
        }

        let (mut result_map_t, mut result_map_2t) = (
            Some(HashMap::<Role, Z>::new()),
            Some(HashMap::<Role, Z>::new()),
        );
        let newly_corrupt = verify_sender_challenge(
            &bcast_data_t,
            session,
            session.threshold() as usize,
            &mut result_map_t,
        )?;

        let newly_corrupt_2t = verify_sender_challenge(
            &bcast_data_2t,
            session,
            2 * session.threshold() as usize,
            &mut result_map_2t,
        )?;

        let result_map_t = result_map_t
            .ok_or_else(|| anyhow_error_and_log("Can not unwrap result_map_t I created."))?;
        let result_map_2t = result_map_2t
            .ok_or_else(|| anyhow_error_and_log("Can not unwrap result_map_2t I created."))?;

        //Merge newly_corrupt into a single set
        bcast_corrupts.extend(newly_corrupt);
        bcast_corrupts.extend(newly_corrupt_2t);
        //Check that reconstructed values are equal for t and 2t
        //Note that parties which are absent from one result_map or the other are already in newly_corrupt
        for (role, value_t) in result_map_t.iter() {
            if let Some(value_2t) = result_map_2t.get(role) {
                if value_2t != value_t {
                    bcast_corrupts.insert(*role);
                }
            }
        }

        //Set 0 share for newly_corrupt senders and add them to corrupt set
        let mut should_return = false;
        for role_pi in bcast_corrupts {
            secrets_shares_all_t.insert(role_pi, vec![Z::ZERO; l]);
            secrets_shares_all_2t.insert(role_pi, vec![Z::ZERO; l]);
            should_return |= session.add_corrupt(role_pi);
        }
        if should_return {
            return Ok(false);
        }

        //Returns as soon as we have a new dispute
        if (!look_for_disputes(&bcast_data_t, session)?)
            || (!look_for_disputes(&bcast_data_2t, session)?)
        {
            return Ok(false);
        }
    }

    //If we reached here, evereything went fine
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(feature = "slow_tests")]
    use crate::execution::communication::broadcast::{Broadcast, SyncReliableBroadcast};
    #[cfg(feature = "slow_tests")]
    use crate::execution::large_execution::{
        coinflip::{Coinflip, RealCoinflip, SecureCoinflip},
        local_double_share::RealLocalDoubleShare,
        share_dispute::RealShareDispute,
        share_dispute::ShareDispute,
        vss::{RealVss, SecureVss, Vss},
    };
    use crate::execution::runtime::sessions::base_session::GenericBaseSessionHandles;
    #[cfg(feature = "slow_tests")]
    use crate::execution::sharing::open::{RobustOpen, SecureRobustOpen};
    #[cfg(feature = "slow_tests")]
    use crate::malicious_execution::large_execution::{
        malicious_coinflip::{DroppingCoinflipAfterVss, MaliciousCoinflipRecons},
        malicious_share_dispute::{
            DroppingShareDispute, MaliciousShareDisputeRecons, WrongShareDisputeRecons,
        },
        malicious_vss::{
            DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart, MaliciousVssR1,
        },
    };

    use crate::algebra::structure_traits::{
        Derive, ErrorCorrect, Invert, Ring, RingWithExceptionalSequence,
    };
    use crate::execution::sharing::shamir::RevealOp;
    use crate::{
        algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
        networking::NetworkMode,
    };
    use crate::{
        execution::{
            large_execution::local_double_share::{LocalDoubleShare, SecureLocalDoubleShare},
            runtime::party::Role,
            runtime::sessions::large_session::{LargeSession, LargeSessionHandles},
            sharing::{shamir::ShamirSharings, share::Share},
        },
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, TestingParameters,
        },
    };
    use aes_prng::AesRng;
    use futures_util::future::join;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::collections::HashSet;

    async fn test_ldl_strategies<
        Z: RingWithExceptionalSequence + Derive + ErrorCorrect + Invert,
        const EXTENSION_DEGREE: usize,
        LD: LocalDoubleShare + 'static,
    >(
        params: TestingParameters,
        malicious_ldl: LD,
    ) {
        let num_secrets = 10_usize;

        let (_, malicious_due_to_dispute) = params.get_dispute_map();

        let mut task_honest = |mut session: LargeSession| async move {
            let real_ldl = SecureLocalDoubleShare::default();
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                real_ldl.execute(&mut session, &secrets).await.unwrap(),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_ldl: LD| async move {
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();

            malicious_ldl.execute(&mut session, &secrets).await
        };

        let mut malicious_roles_with_dispute = HashSet::from_iter(malicious_due_to_dispute);
        malicious_roles_with_dispute.extend(params.malicious_roles.clone());

        //LocalDoubleShare assumes Sync network
        let (result_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.dispute_pairs,
                &malicious_roles_with_dispute,
                malicious_ldl,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            )
            .await;

        //make sure the dispute and malicious set of all honest parties is in sync
        let ref_malicious_set = result_honest[&Role::indexed_from_one(1)].1.clone();
        let ref_dispute_set = result_honest[&Role::indexed_from_one(1)].2.clone();
        for (_, malicious_set, dispute_set) in result_honest.values() {
            assert_eq!(malicious_set, &ref_malicious_set);
            assert_eq!(dispute_set, &ref_dispute_set);
        }

        //If it applies
        //Make sure malicious parties are detected as such
        if params.should_be_detected {
            for role in &malicious_roles_with_dispute {
                assert!(ref_malicious_set.contains(role));
            }
        } else {
            assert!(ref_malicious_set.is_empty());
        }

        //Check that all secrets reconstruct correctly - for parties in malicious set we expect 0
        //For others we expect the real value for both sharings t and 2t
        for sender_id in 1..=params.num_parties {
            let sender_role = Role::indexed_from_one(sender_id);
            let expected_secrets = if ref_malicious_set.contains(&sender_role) {
                (0..num_secrets).map(|_| Z::ZERO).collect_vec()
            } else {
                let mut rng_sender = AesRng::seed_from_u64(sender_id as u64);
                (0..num_secrets)
                    .map(|_| Z::sample(&mut rng_sender))
                    .collect_vec()
            };
            for (secret_id, expected_secret) in expected_secrets.into_iter().enumerate() {
                let mut vec_shares_t = Vec::new();
                let mut vec_shares_2t = Vec::new();
                for (role, (result_ldl, _, _)) in result_honest.iter() {
                    vec_shares_t.push(Share::new(
                        *role,
                        result_ldl.get(&sender_role).unwrap().share_t[secret_id],
                    ));
                    vec_shares_2t.push(Share::new(
                        *role,
                        result_ldl.get(&sender_role).unwrap().share_2t[secret_id],
                    ));
                }
                let shamir_sharing_t = ShamirSharings::create(vec_shares_t);
                let shamir_sharing_2t = ShamirSharings::create(vec_shares_2t);
                let result_t = shamir_sharing_t.reconstruct(params.threshold);
                let result_2t = shamir_sharing_2t.reconstruct(2 * params.threshold);
                assert!(result_t.is_ok());
                assert!(result_2t.is_ok());
                assert_eq!(result_t.unwrap(), expected_secret);
                assert_eq!(result_2t.unwrap(), expected_secret);
            }
        }
    }

    // Rounds (happy path)
    //      share dispute = 1 round
    //      pads =  1 round
    //      coinflip = vss + open = (1 + 3 + t) + 1
    //      verify = m reliable_broadcast = m*(3 + t) rounds
    // with m = div_ceil(DISPUTE_STAT_SEC,Z::LOG_SIZE_EXCEPTIONAL_SET) (=20 for ResiduePolyF4)
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(88)))]
    #[case(TestingParameters::init_honest(7, 2, Some(109)))]
    async fn test_ldl_z128(#[case] params: TestingParameters) {
        let malicious_ldl = SecureLocalDoubleShare::default();

        join(
            test_ldl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
            test_ldl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    async fn test_ldl_malicious_subprotocols_caught<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0,3],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,5,6],&[(1,5),(4,0)],true,None)
        )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] _robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
        #[values(
            DroppingVssFromStart::default(),
            DroppingVssAfterR1::default(),
            MaliciousVssR1::new(&broadcast_strategy,&params.roles_to_lie_to)
        )]
        _vss_strategy: V,
        #[values(
            RealCoinflip::new(_vss_strategy.clone(),_robust_open_strategy.clone()),
            DroppingCoinflipAfterVss::new(_vss_strategy.clone())
        )]
        coinflip_strategy: C,
        #[values(
            RealShareDispute::default(),
            DroppingShareDispute::default(),
            WrongShareDisputeRecons::default(),
            MaliciousShareDisputeRecons::new(&params.roles_to_lie_to)
        )]
        share_dispute_strategy: S,
    ) {
        let malicious_ldl = RealLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        };
        join(
            test_ldl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
            test_ldl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    async fn test_ldl_malicious_subprotocols_not_caught<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],false,None),
            TestingParameters::init(7,2,&[1,4],&[0,2],&[],false,None)
        )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] _robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
        #[values(
            RealVss::new(&broadcast_strategy),
            DroppingVssAfterR2::new(&broadcast_strategy),
            MaliciousVssR1::new(&broadcast_strategy, &params.roles_to_lie_to)
        )]
        _vss_strategy: V,
        #[values(
            RealCoinflip::new(_vss_strategy.clone(),_robust_open_strategy.clone()),
            MaliciousCoinflipRecons::new(_vss_strategy.clone(),_robust_open_strategy.clone()),
        )]
        coinflip_strategy: C,
        #[values(RealShareDispute::default())] share_dispute_strategy: S,
    ) {
        let malicious_ldl = RealLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        };
        join(
            test_ldl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
            test_ldl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
        )
        .await;
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[2],&[0],&[],true,None), SecureCoinflip::default(), MaliciousShareDisputeRecons::new(&params.roles_to_lie_to),SyncReliableBroadcast::default())]
    #[case(TestingParameters::init(4,1,&[2],&[],&[(3,0)],false,None), MaliciousCoinflipRecons::<SecureVss, SecureRobustOpen>::default(), RealShareDispute::default(),SyncReliableBroadcast::default())]
    #[cfg(feature = "slow_tests")]
    async fn test_ldl_malicious_subprotocols_fine_grain<
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
    >(
        #[case] params: TestingParameters,
        #[case] coinflip_strategy: C,
        #[case] share_dispute_strategy: S,
        #[case] broadcast_strategy: BCast,
    ) {
        let malicious_ldl = RealLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        };
        join(
            test_ldl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
            test_ldl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
        )
        .await;
    }

    //Tests for when some parties lie about shares they received
    //Parties should finish after second iteration,
    //catching malicious users only if it lies about too many parties
    #[cfg(feature = "slow_tests")]
    #[rstest]
    async fn test_malicious_receiver_ldl_malicious_subprotocols<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],false,None),
            TestingParameters::init(4,1,&[2],&[0,1],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2],&[],false,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,6],&[(1,2),(4,6)],true,None)
        )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] _robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
        #[values(
            RealVss::new(&broadcast_strategy),
            DroppingVssAfterR2::new(&broadcast_strategy),
            MaliciousVssR1::new(&broadcast_strategy,&params.roles_to_lie_to)
        )]
        _vss_strategy: V,
        #[values(
            RealCoinflip::new(_vss_strategy.clone(),_robust_open_strategy.clone()),
            MaliciousCoinflipRecons::new(_vss_strategy.clone(),_robust_open_strategy.clone()),
        )]
        coinflip_strategy: C,
        #[values(RealShareDispute::default())] share_dispute_strategy: S,
    ) {
        use crate::malicious_execution::large_execution::malicious_local_double_share::MaliciousReceiverLocalDoubleShare;

        let malicious_ldl = MaliciousReceiverLocalDoubleShare::new(
            coinflip_strategy,
            share_dispute_strategy,
            broadcast_strategy,
            &params.roles_to_lie_to,
        );
        join(
            test_ldl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
            test_ldl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
        )
        .await;
    }

    //Tests for when some parties lie about shares they sent
    //Parties should finish after second iteration, catching malicious sender always because it keeps lying
    #[cfg(feature = "slow_tests")]
    #[rstest]
    async fn test_malicious_sender_ldl_malicious_subprotocols<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],true,None),
            TestingParameters::init(4,1,&[2],&[0,1],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,6],&[(1,5),(4,2)],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,3,6],&[(1,0),(4,0)],true,None)
        )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] _robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
        #[values(
            RealVss::new(&broadcast_strategy),
            DroppingVssAfterR2::new(&broadcast_strategy),
            MaliciousVssR1::new(&broadcast_strategy,&params.roles_to_lie_to)
        )]
        _vss_strategy: V,
        #[values(
            RealCoinflip::new(_vss_strategy.clone(),_robust_open_strategy.clone()),
            MaliciousCoinflipRecons::new(_vss_strategy.clone(),_robust_open_strategy.clone()),
        )]
        coinflip_strategy: C,
        #[values(RealShareDispute::default())] share_dispute_strategy: S,
    ) {
        use crate::malicious_execution::large_execution::malicious_local_double_share::MaliciousSenderLocalDoubleShare;

        let malicious_ldl = MaliciousSenderLocalDoubleShare::new(
            coinflip_strategy,
            share_dispute_strategy,
            broadcast_strategy,
            &params.roles_to_lie_to,
        );
        join(
            test_ldl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
            test_ldl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_ldl.clone(),
            ),
        )
        .await;
    }
}
