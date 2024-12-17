use super::{
    coinflip::Coinflip,
    constants::DISPUTE_STAT_SEC,
    local_single_share::{
        compute_check_values, look_for_disputes, verify_sender_challenge, MapsSharesChallenges,
    },
    share_dispute::{ShareDispute, ShareDisputeOutputDouble},
};
use crate::execution::runtime::session::LargeSessionHandles;
use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingEmbed},
    error::error_handler::anyhow_error_and_log,
    execution::{communication::broadcast::broadcast_from_all_w_corruption, runtime::party::Role},
    networking::value::BroadcastValue,
};
use async_trait::async_trait;
use itertools::Itertools;
use kms_common::retry::MAX_ITER;
use num_integer::div_ceil;
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::instrument;

pub struct DoubleShares<Z> {
    pub(crate) share_t: Vec<Z>,
    pub(crate) share_2t: Vec<Z>,
}

#[async_trait]
pub trait LocalDoubleShare: Send + Sync + Default + Clone {
    async fn execute<
        Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
        R: Rng + CryptoRng,
        L: LargeSessionHandles<R>,
    >(
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
pub struct RealLocalDoubleShare<C: Coinflip, S: ShareDispute> {
    coinflip: C,
    share_dispute: S,
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute> LocalDoubleShare for RealLocalDoubleShare<C, S> {
    #[instrument(name="LocalDoubleShare",skip(self,session,secrets),fields(session_id = ?session.session_id(),own_identity=?session.own_identity(),batch_size=?secrets.len()))]
    async fn execute<
        Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
        R: Rng + CryptoRng,
        L: LargeSessionHandles<R>,
    >(
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
        for _ in 0..MAX_ITER {
            //ShareDispute will fill shares from corrupted parties with 0s
            let mut shared_secrets_double =
                self.share_dispute.execute_double(session, secrets).await?;

            let shared_pads_double = send_receive_pads_double(session, &self.share_dispute).await?;

            let x = self.coinflip.execute(session).await?;

            if verify_sharing(
                session,
                &mut shared_secrets_double,
                &shared_pads_double,
                &x,
                secrets.len(),
            )
            .await?
            {
                return format_output(shared_secrets_double);
            }
        }
        Err(anyhow_error_and_log(
            "Failed to verify sharing after {MAX_ITER} iterations for `RealLocalDoubleShare`",
        ))
    }
}

//Format the double sharing correctly for output
fn format_output<Z>(
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
                    "Missing 2t share from party {}",
                    role_pi
                )))
            }
        })
        .try_collect()?;
    Ok(result)
}

async fn send_receive_pads_double<Z, R, L, S>(
    session: &mut L,
    share_dispute: &S,
) -> anyhow::Result<ShareDisputeOutputDouble<Z>>
where
    Z: Ring + RingEmbed + Derive + Invert,
    R: Rng + CryptoRng,
    L: LargeSessionHandles<R>,
    S: ShareDispute,
{
    let m = div_ceil(DISPUTE_STAT_SEC, Z::SIZE_EXCEPTIONAL_SET);
    let my_pads = (0..m).map(|_| Z::sample(session.rng())).collect_vec();
    share_dispute.execute_double(session, &my_pads).await
}

async fn verify_sharing<
    Z: Ring + Derive + ErrorCorrect,
    R: Rng + CryptoRng,
    L: LargeSessionHandles<R>,
>(
    session: &mut L,
    secrets_double: &mut ShareDisputeOutputDouble<Z>,
    pads_double: &ShareDisputeOutputDouble<Z>,
    x: &Z,
    l: usize,
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

    let roles = session.role_assignments().keys().cloned().collect_vec();
    let m = div_ceil(DISPUTE_STAT_SEC, Z::SIZE_EXCEPTIONAL_SET);
    let my_role = session.my_role()?;

    //TODO: Could be done in parallel (to minimize round complexity)
    for g in 0..m {
        let map_challenges = Z::derive_challenges_from_coinflip(x, g.try_into()?, l, &roles);

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

        //Broadcast:
        // - my share of check values on all sharing of degree t and 2t
        // - the shares of all the parties on sharing of degree t and 2t wher I am sender
        let bcast_data = broadcast_from_all_w_corruption(
            session,
            BroadcastValue::LocalDoubleShare((
                map_share_check_values_t,
                map_share_check_values_2t,
                map_share_my_check_values_t,
                map_share_my_check_values_2t,
            )),
        )
        .await?;

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
        for role_pi in bcast_corrupts {
            secrets_shares_all_t.insert(role_pi, vec![Z::ZERO; l]);
            secrets_shares_all_2t.insert(role_pi, vec![Z::ZERO; l]);
            session.add_corrupt(role_pi)?;
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
    use super::{
        anyhow_error_and_log, format_output, send_receive_pads_double, verify_sharing, DoubleShares,
    };
    #[cfg(feature = "slow_tests")]
    use crate::execution::large_execution::{
        coinflip::tests::{DroppingCoinflipAfterVss, MaliciousCoinflipRecons},
        share_dispute::tests::{
            DroppingShareDispute, MaliciousShareDisputeRecons, WrongShareDisputeRecons,
        },
        vss::{
            tests::{DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart, MaliciousVssR1},
            Vss,
        },
    };

    use crate::algebra::structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingEmbed};
    use crate::execution::sharing::shamir::RevealOp;
    use crate::{
        algebra::residue_poly::{ResiduePoly128, ResiduePoly64},
        networking::NetworkMode,
    };
    use crate::{
        execution::{
            large_execution::{
                coinflip::{Coinflip, RealCoinflip},
                local_double_share::{LocalDoubleShare, RealLocalDoubleShare},
                share_dispute::{RealShareDispute, ShareDispute},
                vss::RealVss,
            },
            runtime::party::Role,
            runtime::session::{
                BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
            },
            sharing::{shamir::ShamirSharings, share::Share},
        },
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, roles_from_idxs, TestingParameters,
        },
    };
    use aes_prng::AesRng;
    use async_trait::async_trait;
    use itertools::Itertools;
    use kms_common::retry::MAX_ITER;
    use rand::SeedableRng;
    use rand::{CryptoRng, Rng};
    use rstest::rstest;
    use std::collections::HashMap;

    impl<C: Coinflip, S: ShareDispute> RealLocalDoubleShare<C, S> {
        pub(crate) fn init(
            coinflip_strategy: C,
            share_dispute_strategy: S,
        ) -> RealLocalDoubleShare<C, S> {
            RealLocalDoubleShare {
                coinflip: coinflip_strategy,
                share_dispute: share_dispute_strategy,
            }
        }
    }
    /// Lie in broadcast as sender
    #[derive(Clone, Default)]
    pub(crate) struct MaliciousSenderLocalDoubleShare<C: Coinflip, S: ShareDispute> {
        coinflip: C,
        share_dispute: S,
        roles_to_lie_to: Vec<Role>,
    }
    impl<C: Coinflip, S: ShareDispute> MaliciousSenderLocalDoubleShare<C, S> {
        pub fn init(
            coinflip_strategy: C,
            share_dispute_strategy: S,
            roles_to_lie_to: &[usize],
        ) -> Self {
            Self {
                coinflip: coinflip_strategy,
                share_dispute: share_dispute_strategy,
                roles_to_lie_to: roles_from_idxs(roles_to_lie_to),
            }
        }
    }

    /// Lie in broadcast as receiver
    #[derive(Clone, Default)]
    pub(crate) struct MaliciousReceiverLocalDoubleShare<C: Coinflip, S: ShareDispute> {
        coinflip: C,
        share_dispute: S,
        roles_to_lie_to: Vec<Role>,
    }

    impl<C: Coinflip, S: ShareDispute> MaliciousReceiverLocalDoubleShare<C, S> {
        pub fn init(
            coinflip_strategy: C,
            share_dispute_strategy: S,
            roles_to_lie_to: &[usize],
        ) -> Self {
            Self {
                coinflip: coinflip_strategy,
                share_dispute: share_dispute_strategy,
                roles_to_lie_to: roles_from_idxs(roles_to_lie_to),
            }
        }
    }

    #[async_trait]
    impl<C: Coinflip, S: ShareDispute> LocalDoubleShare for MaliciousSenderLocalDoubleShare<C, S> {
        async fn execute<
            Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
            R: Rng + CryptoRng,
            L: LargeSessionHandles<R>,
        >(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<HashMap<Role, DoubleShares<Z>>> {
            //Keeps executing til verification passes
            for _ in 0..MAX_ITER {
                //ShareDispute will fill shares from corrupted parties with 0s
                let mut shared_secrets_double =
                    self.share_dispute.execute_double(session, secrets).await?;

                let shared_pads =
                    send_receive_pads_double::<Z, R, L, S>(session, &self.share_dispute).await?;

                let x = self.coinflip.execute(session).await?;

                //Pretend I sent other shares to party in roles_to_lie_to
                //Same deviation fro both degree t and 2t
                for role in self.roles_to_lie_to.iter() {
                    let sent_shares_t = shared_secrets_double
                        .output_t
                        .shares_own_secret
                        .get_mut(role)
                        .unwrap();

                    let sent_shares_2t = shared_secrets_double
                        .output_2t
                        .shares_own_secret
                        .get_mut(role)
                        .unwrap();

                    for (share_t, share_2t) in
                        sent_shares_t.iter_mut().zip(sent_shares_2t.iter_mut())
                    {
                        *share_t += Z::ONE;
                        *share_2t += Z::ONE;
                    }
                }

                if verify_sharing(
                    session,
                    &mut shared_secrets_double,
                    &shared_pads,
                    &x,
                    secrets.len(),
                )
                .await?
                {
                    return format_output(shared_secrets_double);
                }
            }
            Err(anyhow_error_and_log(
                "Failed to verify sharing after {MAX_ITER} iterations for `MaliciousSenderLocalDoubleShare`",
            ))
        }
    }

    #[async_trait]
    impl<C: Coinflip, S: ShareDispute> LocalDoubleShare for MaliciousReceiverLocalDoubleShare<C, S> {
        async fn execute<
            Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
            R: Rng + CryptoRng,
            L: LargeSessionHandles<R>,
        >(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<HashMap<Role, DoubleShares<Z>>> {
            //Keeps executing til verification passes
            for _ in 0..MAX_ITER {
                //ShareDispute will fill shares from corrupted parties with 0s
                let mut shared_secrets_double =
                    self.share_dispute.execute_double(session, secrets).await?;

                let shared_pads =
                    send_receive_pads_double::<Z, R, L, S>(session, &self.share_dispute).await?;

                let x = self.coinflip.execute(session).await?;

                //Pretend I received other shares from party in roles_to_lie_to
                //Same deviation fro both degree t and 2t
                for role in self.roles_to_lie_to.iter() {
                    let sent_shares_t = shared_secrets_double
                        .output_t
                        .all_shares
                        .get_mut(role)
                        .unwrap();

                    let sent_shares_2t = shared_secrets_double
                        .output_2t
                        .all_shares
                        .get_mut(role)
                        .unwrap();

                    for (share_t, share_2t) in
                        sent_shares_t.iter_mut().zip(sent_shares_2t.iter_mut())
                    {
                        *share_t += Z::ONE;
                        *share_2t += Z::ONE;
                    }
                }

                if verify_sharing(
                    session,
                    &mut shared_secrets_double,
                    &shared_pads,
                    &x,
                    secrets.len(),
                )
                .await?
                {
                    return format_output(shared_secrets_double);
                }
            }
            Err(anyhow_error_and_log(
                "Failed to verify sharing after {MAX_ITER} iterations for `MaliciousReceiverLocalDoubleShare`",
            ))
        }
    }

    fn test_ldl_strategies<
        Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
        LD: LocalDoubleShare + 'static,
    >(
        params: TestingParameters,
        malicious_ldl: LD,
    ) {
        let num_secrets = 10_usize;

        let (_, malicious_due_to_dispute) = params.get_dispute_map();

        let mut task_honest = |mut session: LargeSession| async move {
            let real_ldl = RealLocalDoubleShare::<TrueCoinFlip, RealShareDispute>::default();
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role().unwrap(),
                real_ldl.execute(&mut session, &secrets).await.unwrap(),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_ldl: LD| async move {
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role().unwrap(),
                malicious_ldl.execute(&mut session, &secrets).await,
            )
        };

        //LocalDoubleShare assumes Sync network
        let (result_honest, _) = execute_protocol_large_w_disputes_and_malicious::<Z, _, _, _, _, _>(
            &params,
            &params.dispute_pairs,
            &[
                malicious_due_to_dispute.clone(),
                params.malicious_roles.to_vec(),
            ]
            .concat(),
            malicious_ldl,
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

        //Check that all secrets reconstruct correctly - for parties in malicious set we expect 0
        //For others we expect the real value for both sharings t and 2t
        for sender_id in 0..params.num_parties {
            let sender_role = Role::indexed_by_zero(sender_id);
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
                for (role, result_ldl, _, _) in result_honest.iter() {
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

    type TrueCoinFlip = RealCoinflip<RealVss>;

    // Rounds (happy path)
    //      share dispute = 1 round
    //      pads =  1 round
    //      coinflip = vss + open = (1 + 3 + t) + 1
    //      verify = 1 reliable_broadcast = 3 + t rounds
    // Total: 10 + 2*t rounds
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(12)))]
    #[case(TestingParameters::init_honest(7, 2, Some(14)))]
    fn test_ldl_z128(#[case] params: TestingParameters) {
        let malicious_ldl = RealLocalDoubleShare::<TrueCoinFlip, RealShareDispute>::default();

        test_ldl_strategies::<ResiduePoly64, _>(params.clone(), malicious_ldl.clone());
        test_ldl_strategies::<ResiduePoly128, _>(params.clone(), malicious_ldl.clone());
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_ldl_malicious_subprotocols_caught<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0,3],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,5,6],&[(1,5),(4,0)],true,None)
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
        coinflip_strategy: C,
        #[values(
            RealShareDispute::default(),
            DroppingShareDispute::default(),
            WrongShareDisputeRecons::default(),
            MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)
        )]
        share_dispute_strategy: S,
    ) {
        let malicious_ldl = RealLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
        };
        test_ldl_strategies::<ResiduePoly64, _>(params.clone(), malicious_ldl.clone());
        test_ldl_strategies::<ResiduePoly128, _>(params.clone(), malicious_ldl.clone());
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_ldl_malicious_subprotocols_not_caught<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],false,None),
            TestingParameters::init(7,2,&[1,4],&[0,2],&[],false,None)
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
        coinflip_strategy: C,
        #[values(RealShareDispute::default())] share_dispute_strategy: S,
    ) {
        let malicious_ldl = RealLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
        };
        test_ldl_strategies::<ResiduePoly64, _>(params.clone(), malicious_ldl.clone());
        test_ldl_strategies::<ResiduePoly128, _>(params.clone(), malicious_ldl.clone());
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    #[case(TestingParameters::init(4,1,&[2],&[0],&[],true,None), TrueCoinFlip::default(), MaliciousShareDisputeRecons::init(&params.roles_to_lie_to))]
    #[case(TestingParameters::init(4,1,&[2],&[],&[(3,0)],false,None), MaliciousCoinflipRecons::<RealVss>::default(), RealShareDispute::default())]
    fn test_ldl_malicious_subprotocols_fine_grain<
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[case] params: TestingParameters,
        #[case] coinflip_strategy: C,
        #[case] share_dispute_strategy: S,
    ) {
        let malicious_ldl = RealLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
        };
        test_ldl_strategies::<ResiduePoly64, _>(params.clone(), malicious_ldl.clone());
        test_ldl_strategies::<ResiduePoly128, _>(params.clone(), malicious_ldl.clone());
    }

    //Tests for when some parties lie about shares they received
    //Parties should finish after second iteration,
    //catching malicious users only if it lies about too many parties
    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_malicious_receiver_ldl_malicious_subprotocols<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],false,None),
            TestingParameters::init(4,1,&[2],&[0,1],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2],&[],false,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,6],&[(1,2),(4,6)],true,None)
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
        coinflip_strategy: C,
        #[values(RealShareDispute::default())] share_dispute_strategy: S,
    ) {
        let malicious_ldl = MaliciousReceiverLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            roles_to_lie_to: roles_from_idxs(&params.roles_to_lie_to),
        };
        test_ldl_strategies::<ResiduePoly64, _>(params.clone(), malicious_ldl.clone());
        test_ldl_strategies::<ResiduePoly128, _>(params.clone(), malicious_ldl.clone());
    }

    //Tests for when some parties lie about shares they sent
    //Parties should finish after second iteration, catching malicious sender always because it keeps lying
    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_malicious_sender_ldl_malicious_subprotocols<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],true,None),
            TestingParameters::init(4,1,&[2],&[0,1],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,6],&[(1,5),(4,2)],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,3,6],&[(1,0),(4,0)],true,None)
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
        coinflip_strategy: C,
        #[values(RealShareDispute::default())] share_dispute_strategy: S,
    ) {
        let malicious_ldl = MaliciousSenderLocalDoubleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            roles_to_lie_to: roles_from_idxs(&params.roles_to_lie_to),
        };
        test_ldl_strategies::<ResiduePoly64, _>(params.clone(), malicious_ldl.clone());
        test_ldl_strategies::<ResiduePoly128, _>(params.clone(), malicious_ldl.clone());
    }
}
