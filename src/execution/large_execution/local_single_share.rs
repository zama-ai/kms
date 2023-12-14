use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::broadcast_with_corruption,
        runtime::party::Role,
        runtime::session::LargeSessionHandles,
        sharing::{
            shamir::{ShamirRing, ShamirSharing},
            share::Share,
        },
    },
    networking::value::BroadcastValue,
};

use super::{
    coinflip::Coinflip,
    constants::DISPUTE_STAT_SEC,
    share_dispute::{ShareDispute, ShareDisputeOutput},
};

use async_trait::async_trait;
use itertools::Itertools;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

///Trait required to execute local and double single share, need to be able to derive many values from ones (by hashing)
pub trait Derive: Sized {
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: usize,
        l: usize,
        roles: &[Role],
    ) -> HashMap<Role, Vec<Self>>;
}

#[async_trait]
pub trait LocalSingleShare: Send + Sync + Default + Clone {
    ///Executes a batch LocalSingleShare where every party is sharing a vector of secrets
    ///
    ///NOTE: This does not always guarantee privacy of the inputs towards honest parties (but this is intended behaviour!)
    ///
    ///Inputs:
    /// - rng as the random number generator
    /// - session as the MPC session
    /// - secrets as the vector of secrets I want to share
    /// - dispute as the dispute set (can be mutated)
    ///
    /// Output:
    /// - A HashMap that maps role to the vector of shares receive from that party (including my own shares).
    /// Corrupt parties are mapped to the default 0 sharing
    async fn execute<Z: ShamirRing + Derive, R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, Vec<Z>>>;
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct MapsSharesChallenges<Z> {
    pub(crate) checks_for_all: BTreeMap<Role, Z>,
    pub(crate) checks_for_mine: BTreeMap<Role, Z>,
}

/// We expect instances of:
/// - [Coinflip]
/// - [ShareDispute]
#[derive(Default, Clone)]
pub struct RealLocalSingleShare<C: Coinflip, S: ShareDispute> {
    coinflip: C,
    share_dispute: S,
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute> LocalSingleShare for RealLocalSingleShare<C, S> {
    async fn execute<Z: ShamirRing + Derive, R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, Vec<Z>>> {
        if secrets.is_empty() {
            return Err(anyhow_error_and_log(
                "Passed an empty secrets vector to LocalSingleShare".to_string(),
            ));
        }
        //Keeps executing til verification passes
        loop {
            //ShareDispute will fill shares from corrupted players with 0s
            let mut shared_secrets = self.share_dispute.execute(session, secrets).await?;

            let shared_pads = send_receive_pads(session, &self.share_dispute).await?;

            let x = self.coinflip.execute(session).await?;

            if verify_sharing(
                session,
                &mut shared_secrets,
                &shared_pads,
                &x,
                secrets.len(),
            )
            .await?
            {
                return Ok(shared_secrets.all_shares);
            }
        }
    }
}

async fn send_receive_pads<Z, R, L, S>(
    session: &mut L,
    share_dispute: &S,
) -> anyhow::Result<ShareDisputeOutput<Z>>
where
    Z: ShamirRing,
    R: RngCore,
    L: LargeSessionHandles<R>,
    S: ShareDispute,
{
    let m = (DISPUTE_STAT_SEC as f64 / Z::BIT_LENGTH as f64).ceil() as usize;
    let my_pads = (0..m).map(|_| Z::sample(session.rng())).collect_vec();
    share_dispute.execute(session, &my_pads).await
}

async fn verify_sharing<Z: ShamirRing + Derive, R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    secrets: &mut ShareDisputeOutput<Z>,
    pads: &ShareDisputeOutput<Z>,
    x: &Z,
    l: usize,
) -> anyhow::Result<bool> {
    let (secrets_shares_all, my_shared_secrets) =
        (&mut secrets.all_shares, &mut secrets.shares_own_secret);
    let (pads_shares_all, my_shared_pads) = (&pads.all_shares, &pads.shares_own_secret);
    let m = (DISPUTE_STAT_SEC as f64 / Z::BIT_LENGTH as f64).ceil() as usize;
    let roles = session.role_assignments().keys().cloned().collect_vec();
    let my_role = session.my_role()?;
    let mut result = true;
    for g in 0..m {
        let map_challenges = Z::derive_challenges_from_coinflip(x, g, l, &roles);

        //Compute my share of check values for every local single share happening in parallel
        let map_share_check_values = compute_check_values(
            pads_shares_all,
            &map_challenges,
            secrets_shares_all,
            g,
            None,
        )?;

        //Compute the share of the check value for MY local single share
        let map_share_my_check_values = compute_check_values(
            my_shared_pads,
            &map_challenges,
            my_shared_secrets,
            g,
            Some(&my_role.clone()),
        )?;

        //Broadcast both my share of check values on all lsl as well as all the shares of check values for lsl where I am sender
        //All roles will be mapped to an output, but it may be Bot if they are malicious
        let bcast_data = broadcast_with_corruption(
            session,
            BroadcastValue::LocalSingleShare(MapsSharesChallenges {
                checks_for_all: map_share_check_values,
                checks_for_mine: map_share_my_check_values,
            }),
        )
        .await?;

        //Map broadcast data back to MapSharesChallenges
        let mut bcast_output = HashMap::new();
        let mut bcast_corrupts = HashSet::new();
        for (role, bcast_value) in bcast_data {
            if let BroadcastValue::LocalSingleShare(value) = bcast_value {
                bcast_output.insert(role, value);
            } else {
                bcast_corrupts.insert(role);
            }
        }

        let newly_corrupts = verify_sender_challenge(
            &bcast_output,
            session,
            session.threshold() as usize,
            &mut None,
        )?;
        bcast_corrupts.extend(newly_corrupts);
        //Set 0 share for newly_corrupt senders and add them to the corrupt set
        for role_pi in bcast_corrupts {
            secrets_shares_all.insert(role_pi, vec![Z::ZERO; l]);
            session.add_corrupt(role_pi)?;
        }

        result &= look_for_disputes(&bcast_output, session)?;
    }
    Ok(result)
}

// Inputs:
// pads_shares maps a role to a vector of size m ( { r_g }_g in the protocol description)
// map_challenges maps a role to a vector of size l ( { x_{jg} }_j in the protocol description)
// secret_shares maps a role to a vector of size l ( { s_j }_j in the protocol description)
// Output:
// the share of the checking value for every role
pub(crate) fn compute_check_values<Z: Ring>(
    map_pads_shares: &HashMap<Role, Vec<Z>>,
    map_challenges: &HashMap<Role, Vec<Z>>,
    map_secret_shares: &HashMap<Role, Vec<Z>>,
    g: usize,
    my_role: Option<&Role>,
) -> anyhow::Result<BTreeMap<Role, Z>> {
    map_pads_shares
        .iter()
        .map(|(role, pads_shares)| {
            let role_to_fetch = my_role.unwrap_or(role);
            let vec_challenges = map_challenges
                .get(role_to_fetch)
                //Should never fail because ShareDispute fills the result with default 0 values
                .ok_or_else(|| anyhow_error_and_log("Can not retrieve challenges".to_string()))?;
            //Should never fail because ShareDispute fills the result with default 0 values
            let vec_secret_shares = map_secret_shares.get(role).ok_or_else(|| {
                anyhow_error_and_log("Can not retrieve secret shares".to_string())
            })?;
            Ok((
                *role,
                pads_shares[g]
                    + vec_challenges
                        .iter()
                        .zip(vec_secret_shares.iter())
                        .fold(Z::ZERO, |acc, (x, s)| acc + *x * *s),
            ))
        })
        .try_collect()
}

//Verify that the sender for each lsl did give a 0 share to parties it is in dispute with
//and that the overall sharing is a degree t polynomial
pub(crate) fn verify_sender_challenge<Z: ShamirRing, R: RngCore, L: LargeSessionHandles<R>>(
    bcast_data: &HashMap<Role, MapsSharesChallenges<Z>>,
    session: &mut L,
    threshold: usize,
    result_map: &mut Option<HashMap<Role, Z>>,
) -> anyhow::Result<HashSet<Role>> {
    let mut newly_corrupt = HashSet::<Role>::new();

    for (role_pi, bcast_value) in bcast_data {
        let sharing_from_sender = &bcast_value.checks_for_mine;
        //Make sure the current sender has sent a value to check against for all parties
        if sharing_from_sender.keys().collect::<HashSet<&Role>>()
            != session
                .role_assignments()
                .keys()
                .collect::<HashSet<&Role>>()
        {
            newly_corrupt.insert(*role_pi);
            tracing::warn!("Party {role_pi} did not send a check value for all parties, adding it to the corrupt set");
            continue;
        }

        //Check parties in dispute with pi have shares = 0
        //This should never fail, if there is no dispute the set is empty but exists
        let parties_dispute_pi = session.disputed_roles().get(role_pi)?;
        for pj_dispute_pi in parties_dispute_pi {
            //Only add pi to corrupt if pj isn't corrupt AND if sharing from pi to pj is not zero
            if !session.corrupt_roles().contains(pj_dispute_pi)
                && sharing_from_sender
                    .get(pj_dispute_pi)
                    //This should never fail due to the above check
                    .ok_or_else(|| {
                        anyhow_error_and_log(
                            "Can not find the share for {pj_dispute_pi}".to_string(),
                        )
                    })?
                    != &Z::ZERO
            {
                newly_corrupt.insert(*role_pi);
                tracing::warn!("Expected to find a 0 share for {pj_dispute_pi} from {role_pi} due to dispute. Adding it to corrupt");
                break;
            }
        }
        if !newly_corrupt.contains(role_pi) {
            //Check correct degree
            let sharing = sharing_from_sender
                .iter()
                .map(|(role, share)| Share::new(*role, *share))
                .collect_vec();
            let sharing = ShamirSharing::create(sharing);
            let try_reconstruct = sharing.err_reconstruct(threshold, 0);

            if let Ok(value) = try_reconstruct {
                if let Some(result_map) = result_map {
                    result_map.insert(*role_pi, value);
                }
            } else {
                tracing::warn!(
                    "Reconstruction from {role_pi} failed, adding it to corrupt. {:?}",
                    try_reconstruct
                );
                newly_corrupt.insert(*role_pi);
            }
        }
    }

    Ok(newly_corrupt)
}

pub(crate) fn look_for_disputes<Z: Ring, R: RngCore, L: LargeSessionHandles<R>>(
    bcast_data: &HashMap<Role, MapsSharesChallenges<Z>>,
    session: &mut L,
) -> anyhow::Result<bool> {
    let mut everything_ok = true;

    for (role_sender, bcast_value) in bcast_data {
        if !session.corrupt_roles().contains(role_sender) {
            //This should never fail, if there is no dispute the set is empty but exists
            let sender_dispute_set = session.disputed_roles().get(role_sender)?.clone();
            //Senders that have wrong type are already in the corrupt set from before, so no need for an else clause
            let sender_vote = &bcast_value.checks_for_mine;
            //Similarly, we know that sender maps all the parties to something from before
            for (role_receiver, sender_value) in sender_vote {
                //If the receiver is in dispute with the sender, its value is defined to be 0
                //and we checked that the sender did send a 0 in [verify_sender_challenge]
                //If the receiver is corrupt, we just dont take its opinion into account
                if !session.corrupt_roles().contains(role_receiver)
                    && !sender_dispute_set.contains(role_receiver)
                {
                    //This should never fail, as bcast maps all roles to some output (might be Bot)
                    let receiver_bcast_value = bcast_data.get(role_receiver).ok_or_else(|| {
                        anyhow_error_and_log(
                            "Can not find receiver {role_receiver} in broadcast data".to_string(),
                        )
                    })?;
                    let receiver_value = &receiver_bcast_value.checks_for_all.get(role_sender);

                    //If sender and receiver don't agree, add (pi,pj) to dispute
                    match receiver_value {
                        Some(rcv_value) if *rcv_value == sender_value => {}
                        _ => {
                            tracing::warn!("Parties {role_receiver} and Sender {role_sender} disagree on the checking value. Add a dispute");
                            session.add_dispute(role_receiver, role_sender)?;
                            everything_ok = false;
                        }
                    }
                }
            }
        }
    }
    Ok(everything_ok)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        send_receive_pads, verify_sharing, Derive, LocalSingleShare, RealLocalSingleShare,
    };
    use crate::algebra::residue_poly::ResiduePoly128;
    use crate::algebra::residue_poly::ResiduePoly64;
    #[cfg(feature = "extensive_testing")]
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
    use crate::{
        execution::{
            large_execution::{
                coinflip::{Coinflip, RealCoinflip},
                share_dispute::{RealShareDispute, ShareDispute},
                vss::RealVss,
            },
            runtime::party::Role,
            runtime::session::{
                BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
            },
            sharing::{
                shamir::{ShamirRing, ShamirSharing},
                share::Share,
            },
        },
        tests::helper::tests::{
            execute_protocol_w_disputes_and_malicious, roles_from_idxs, TestingParameters,
        },
    };

    use async_trait::async_trait;
    use itertools::Itertools;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rstest::rstest;
    use std::collections::HashMap;

    impl<C: Coinflip, S: ShareDispute> RealLocalSingleShare<C, S> {
        pub(crate) fn init(
            coinflip_strategy: C,
            share_dispute_strategy: S,
        ) -> RealLocalSingleShare<C, S> {
            RealLocalSingleShare {
                coinflip: coinflip_strategy,
                share_dispute: share_dispute_strategy,
            }
        }
    }

    /// Lie in broadcast as sender
    #[derive(Clone, Default)]
    pub(crate) struct MaliciousSenderLocalSingleShare<C: Coinflip, S: ShareDispute> {
        coinflip: C,
        share_dispute: S,
        roles_to_lie_to: Vec<Role>,
    }

    impl<C: Coinflip, S: ShareDispute> MaliciousSenderLocalSingleShare<C, S> {
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
    pub(crate) struct MaliciousReceiverLocalSingleShare<C: Coinflip, S: ShareDispute> {
        coinflip: C,
        share_dispute: S,
        roles_to_lie_to: Vec<Role>,
    }

    impl<C: Coinflip, S: ShareDispute> MaliciousReceiverLocalSingleShare<C, S> {
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
    impl<C: Coinflip, S: ShareDispute> LocalSingleShare for MaliciousSenderLocalSingleShare<C, S> {
        async fn execute<Z: ShamirRing + Derive, R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<HashMap<Role, Vec<Z>>> {
            //Keeps executing til verification passes
            loop {
                //ShareDispute will fill shares from corrupted players with 0s
                let mut shared_secrets = self.share_dispute.execute(session, secrets).await?;

                let shared_pads =
                    send_receive_pads::<Z, R, L, S>(session, &self.share_dispute).await?;

                let x = self.coinflip.execute(session).await?;

                //Pretend I sent other shares to party in roles_to_lie_to
                for (sent_role, sent_shares) in shared_secrets.shares_own_secret.iter_mut() {
                    if self.roles_to_lie_to.contains(sent_role) {
                        let modified_sent_shares = sent_shares
                            .iter()
                            .map(|share| *share + Z::ONE)
                            .collect_vec();
                        *sent_shares = modified_sent_shares;
                    }
                }
                if verify_sharing(
                    session,
                    &mut shared_secrets,
                    &shared_pads,
                    &x,
                    secrets.len(),
                )
                .await?
                {
                    return Ok(shared_secrets.all_shares);
                }
            }
        }
    }

    #[async_trait]
    impl<C: Coinflip, S: ShareDispute> LocalSingleShare for MaliciousReceiverLocalSingleShare<C, S> {
        async fn execute<Z: ShamirRing + Derive, R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<HashMap<Role, Vec<Z>>> {
            loop {
                //ShareDispute will fill shares from corrupted players with 0s
                let mut shared_secrets = self.share_dispute.execute(session, secrets).await?;

                let shared_pads =
                    send_receive_pads::<Z, R, L, S>(session, &self.share_dispute).await?;

                let x = self.coinflip.execute(session).await?;

                //Pretend I received other shares from party in roles_to_lie_to
                for (rcv_role, rcv_shares) in shared_secrets.all_shares.iter_mut() {
                    if self.roles_to_lie_to.contains(rcv_role) {
                        let modified_rcv_shares =
                            rcv_shares.iter().map(|share| *share + Z::ONE).collect_vec();
                        *rcv_shares = modified_rcv_shares;
                    }
                }
                if verify_sharing(
                    session,
                    &mut shared_secrets,
                    &shared_pads,
                    &x,
                    secrets.len(),
                )
                .await?
                {
                    return Ok(shared_secrets.all_shares);
                }
            }
        }
    }

    fn test_lsl_strategies<Z: ShamirRing + Derive, L: LocalSingleShare + 'static>(
        params: TestingParameters,
        malicious_lsl: L,
    ) {
        let nb_secrets = 10_usize;

        let (_, malicious_due_to_dispute) = params.get_dispute_map();

        let mut task_honest = |mut session: LargeSession| async move {
            let real_lsl = RealLocalSingleShare::<TrueCoinFlip, RealShareDispute>::default();
            let secrets = (0..nb_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role().unwrap(),
                real_lsl.execute(&mut session, &secrets).await.unwrap(),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_lsl: L| async move {
            let secrets = (0..nb_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role().unwrap(),
                malicious_lsl.execute(&mut session, &secrets).await,
            )
        };

        let (result_honest, _) = execute_protocol_w_disputes_and_malicious::<Z, _, _, _, _, _>(
            params.num_parties,
            params.threshold as u8,
            &params.dispute_pairs,
            &[
                malicious_due_to_dispute.clone(),
                params.malicious_roles.to_vec(),
            ]
            .concat(),
            malicious_lsl,
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
        //For others we expect the real value
        for sender_id in 0..params.num_parties {
            let sender_role = Role::indexed_by_zero(sender_id);
            let expected_secrets = if ref_malicious_set.contains(&sender_role) {
                (0..nb_secrets).map(|_| Z::ZERO).collect_vec()
            } else {
                let mut rng_sender = ChaCha20Rng::seed_from_u64(sender_id as u64);
                (0..nb_secrets)
                    .map(|_| Z::sample(&mut rng_sender))
                    .collect_vec()
            };
            for (secret_id, expected_secret) in expected_secrets.into_iter().enumerate() {
                let mut vec_shares = Vec::new();
                for (role, result_lsl, _, _) in result_honest.iter() {
                    vec_shares.push(Share::new(
                        *role,
                        result_lsl.get(&sender_role).unwrap()[secret_id],
                    ));
                }
                let shamir_sharing = ShamirSharing::create(vec_shares);
                let result = shamir_sharing.reconstruct(params.threshold);
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), expected_secret);
            }
        }
    }

    type TrueCoinFlip = RealCoinflip<RealVss>;
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1))]
    #[case(TestingParameters::init_honest(7, 2))]
    fn test_lsl_z128(#[case] params: TestingParameters) {
        let malicious_lsl = RealLocalSingleShare::<TrueCoinFlip, RealShareDispute>::default();
        test_lsl_strategies::<ResiduePoly64, _>(params.clone(), malicious_lsl.clone());
        test_lsl_strategies::<ResiduePoly128, _>(params.clone(), malicious_lsl.clone());
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    fn test_lsl_malicious_subprotocols_caught<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0,3],&[],true),
            TestingParameters::init(7,2,&[1,4],&[0,2,5,6],&[],true)
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
        let malicious_lsl = RealLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
        };
        test_lsl_strategies::<ResiduePoly64, _>(params.clone(), malicious_lsl.clone());
        test_lsl_strategies::<ResiduePoly128, _>(params.clone(), malicious_lsl.clone());
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    fn test_lsl_malicious_subprotocols_not_caught<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],false),
            TestingParameters::init(7,2,&[1,4],&[0,2],&[],false)
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
        let malicious_lsl = RealLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
        };

        test_lsl_strategies::<ResiduePoly64, _>(params.clone(), malicious_lsl.clone());
        test_lsl_strategies::<ResiduePoly128, _>(params.clone(), malicious_lsl.clone());
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    #[case(TestingParameters::init(4,1,&[2],&[0],&[],true), TrueCoinFlip::default(), MaliciousShareDisputeRecons::init(&params.roles_to_lie_to))]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],false), MaliciousCoinflipRecons::<RealVss>::default(), RealShareDispute::default())]
    fn test_lsl_malicious_subprotocols_fine_grain<
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[case] params: TestingParameters,
        #[case] coinflip_strategy: C,
        #[case] share_dispute_strategy: S,
    ) {
        let malicious_lsl = RealLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
        };
        test_lsl_strategies::<ResiduePoly64, _>(params.clone(), malicious_lsl.clone());
        test_lsl_strategies::<ResiduePoly128, _>(params.clone(), malicious_lsl.clone());
    }

    //Tests for when some parties lie about shares they received
    //Parties should finish after second iteration,
    //catching malicious users only if it lies about too many parties
    #[cfg(feature = "extensive_testing")]
    #[rstest]
    fn test_malicious_receiver_lsl_malicious_subprotocols<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],false),
            TestingParameters::init(4,1,&[2],&[0,1],&[],true),
            TestingParameters::init(7,2,&[1,4],&[0,2],&[],false),
            TestingParameters::init(7,2,&[1,4],&[0,2,6],&[],true)
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
        let malicious_lsl = MaliciousReceiverLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            roles_to_lie_to: roles_from_idxs(&params.roles_to_lie_to),
        };
        test_lsl_strategies::<ResiduePoly64, _>(params.clone(), malicious_lsl.clone());
        test_lsl_strategies::<ResiduePoly128, _>(params.clone(), malicious_lsl.clone());
    }

    //Tests for when some parties lie about shares they sent
    //Parties should finish after second iteration, catching malicious sender always because it keeps lying
    #[cfg(feature = "extensive_testing")]
    #[rstest]
    fn test_malicious_sender_lsl_malicious_subprotocols<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],true),
            TestingParameters::init(4,1,&[2],&[0,1],&[],true),
            TestingParameters::init(7,2,&[1,4],&[0,6],&[],true),
            TestingParameters::init(7,2,&[1,4],&[0,2,3,6],&[],true)
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
        let malicious_lsl = MaliciousSenderLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            roles_to_lie_to: roles_from_idxs(&params.roles_to_lie_to),
        };
        test_lsl_strategies::<ResiduePoly64, _>(params.clone(), malicious_lsl.clone());
        test_lsl_strategies::<ResiduePoly128, _>(params.clone(), malicious_lsl.clone());
    }
}
