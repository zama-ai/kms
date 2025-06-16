use super::{
    coinflip::{Coinflip, SecureCoinflip},
    constants::DISPUTE_STAT_SEC,
    share_dispute::{SecureShareDispute, ShareDispute, ShareDisputeOutput},
};
use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingEmbed},
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::{Broadcast, SyncReliableBroadcast},
        runtime::{party::Role, session::LargeSessionHandles},
        sharing::{
            shamir::{RevealOp, ShamirSharings},
            share::Share,
        },
    },
    networking::value::BroadcastValue,
    ProtocolDescription,
};
use async_trait::async_trait;
use itertools::Itertools;
use num_integer::div_ceil;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::instrument;

pub(crate) const LOCAL_SINGLE_MAX_ITER: usize = 30;

pub type SecureLocalSingleShare =
    RealLocalSingleShare<SecureCoinflip, SecureShareDispute, SyncReliableBroadcast>;

#[async_trait]
pub trait LocalSingleShare: ProtocolDescription + Send + Sync + Clone {
    ///Executes a batch LocalSingleShare where every party is sharing a vector of secrets
    ///
    ///NOTE: This does not always guarantee privacy of the inputs towards honest parties (but this is intended behaviour!)
    ///
    ///Inputs:
    /// - session as the MPC session
    /// - secrets as the vector of secrets I want to share
    ///
    /// Output:
    /// - A HashMap that maps role to the vector of shares receive from that party (including my own shares).
    /// Corrupt parties are mapped to the default 0 sharing
    async fn execute<Z: Ring + RingEmbed + Invert + Derive + ErrorCorrect, L: LargeSessionHandles>(
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
pub struct RealLocalSingleShare<C: Coinflip, S: ShareDispute, BCast: Broadcast> {
    coinflip: C,
    share_dispute: S,
    broadcast: BCast,
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> ProtocolDescription
    for RealLocalSingleShare<C, S, BCast>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-RealLocalSingleShare:\n{}\n{}\n{}",
            indent,
            C::protocol_desc(depth + 1),
            S::protocol_desc(depth + 1),
            BCast::protocol_desc(depth + 1)
        )
    }
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> RealLocalSingleShare<C, S, BCast> {
    pub fn new(coinflip_strategy: C, share_dispute_strategy: S, broadcast_strategy: BCast) -> Self {
        RealLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        }
    }
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> LocalSingleShare
    for RealLocalSingleShare<C, S, BCast>
{
    #[instrument(name="LocalSingleShare",skip(self,session,secrets),fields(sid = ?session.session_id(),own_identity=?session.own_identity(),batch_size = ?secrets.len()))]
    async fn execute<
        Z: Ring + RingEmbed + Invert + Derive + ErrorCorrect,
        L: LargeSessionHandles,
    >(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, Vec<Z>>> {
        if secrets.is_empty() {
            return Err(anyhow_error_and_log(
                "Passed an empty secrets vector to LocalSingleShare".to_string(),
            ));
        }

        // Keeps executing until verification passes, excluding malicious players every time it does not
        for _ in 0..LOCAL_SINGLE_MAX_ITER {
            let mut shared_secrets;
            let mut x;
            let mut shared_pads;

            // The following loop is guaranteed to terminate.
            // We we will leave it once the corrupt set does not change.
            // This happens right away on the happy path or worst case after all parties are in there and no new parties can be added.
            loop {
                let corrupt_start = session.corrupt_roles().clone();

                // ShareDispute will fill shares from disputed parties with 0s
                // <s>
                shared_secrets = self.share_dispute.execute(session, secrets).await?;

                // note that we could merge the share_pads round into the first one.
                // This is currently discussed in the NIST doc
                // <r>
                shared_pads = send_receive_pads(session, &self.share_dispute).await?;

                x = self.coinflip.execute(session).await?;

                // if the corrupt roles have not changed, we can exit the loop and move on, otherwise start from the top
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }

            if verify_sharing(
                session,
                &mut shared_secrets,
                &shared_pads,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                return Ok(shared_secrets.all_shares);
            }
        }
        Err(anyhow_error_and_log(
            "Failed to verify sharing after {LOCAL_SINGLE_MAX_ITER} iterations for `RealLocalSingleShare`",
        ))
    }
}

pub(crate) async fn send_receive_pads<Z, L, S>(
    session: &mut L,
    share_dispute: &S,
) -> anyhow::Result<ShareDisputeOutput<Z>>
where
    Z: Ring + RingEmbed + Derive + Invert,
    L: LargeSessionHandles,
    S: ShareDispute,
{
    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let my_pads = (0..m).map(|_| Z::sample(session.rng())).collect_vec();
    share_dispute.execute(session, &my_pads).await
}

pub(crate) async fn verify_sharing<
    Z: Ring + Derive + ErrorCorrect,
    L: LargeSessionHandles,
    BCast: Broadcast,
>(
    session: &mut L,
    secrets: &mut ShareDisputeOutput<Z>,
    pads: &ShareDisputeOutput<Z>,
    x: &Z,
    l: usize,
    broadcast: &BCast,
) -> anyhow::Result<bool> {
    let (secrets_shares_all, my_shared_secrets) =
        (&mut secrets.all_shares, &mut secrets.shares_own_secret);
    let (pads_shares_all, my_shared_pads) = (&pads.all_shares, &pads.shares_own_secret);
    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let roles = session.role_assignments().keys().cloned().collect_vec();
    let my_role = session.my_role();
    //TODO: Could be done in parallel (to minimize round complexity)
    for g in 0..m {
        tracing::warn!("I AM {my_role} DOING LOOP OF LSL {g} out of {m}");
        let map_challenges = Z::derive_challenges_from_coinflip(x, g.try_into()?, l, &roles);

        //Compute my share of check values for every local single share happening in parallel
        //<y>
        let map_share_check_values = compute_check_values(
            pads_shares_all,
            &map_challenges,
            secrets_shares_all,
            g,
            None,
        )?;

        //Compute the share of the check value for MY local single share
        //<y^*>_j
        let map_share_my_check_values = compute_check_values(
            my_shared_pads,
            &map_challenges,
            my_shared_secrets,
            g,
            Some(&my_role.clone()),
        )?;

        let corrupt_before_bc = session.corrupt_roles().clone();

        //Broadcast both my share of check values on all lsl as well as all the shares of check values for lsl where I am sender
        //All roles will be mapped to an output, but it may be Bot if they are malicious
        // Step (d)
        let bcast_data = broadcast
            .broadcast_from_all_w_corrupt_set_update(
                session,
                BroadcastValue::LocalSingleShare(MapsSharesChallenges {
                    checks_for_all: map_share_check_values,
                    checks_for_mine: map_share_my_check_values,
                }),
            )
            .await?;

        // If the corrupt roles have not changed, we can continue, otherwise start from beginning
        if *session.corrupt_roles() != corrupt_before_bc {
            return Ok(false);
        }

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
        let mut should_return = false;
        for role_pi in bcast_corrupts {
            secrets_shares_all.insert(role_pi, vec![Z::ZERO; l]);
            should_return |= session.add_corrupt(role_pi)?;
        }

        tracing::error!("RESTARTING EVERYTHING AS WE DETECTED MALICIOUS BEHAVIOUR");
        if should_return {
            return Ok(false);
        }

        //Returns as soon as we have a new dispute
        if !look_for_disputes(&bcast_output, session)? {
            return Ok(false);
        }
    }

    //If we reached here, everything went fine
    Ok(true)
}

// Inputs:
// map_pads_shares maps a role to a vector of size m ( { r_g }_g in the protocol description)
// map_challenges maps a role to a vector of size l ( { x_{jg} }_j in the protocol description)
// map_secret_shares maps a role to a vector of size l ( { s_j }_j in the protocol description)
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
pub(crate) fn verify_sender_challenge<Z: Ring + ErrorCorrect, L: LargeSessionHandles>(
    bcast_data: &HashMap<Role, MapsSharesChallenges<Z>>,
    session: &mut L,
    threshold: usize,
    result_map: &mut Option<HashMap<Role, Z>>,
) -> anyhow::Result<HashSet<Role>> {
    let mut newly_corrupt = HashSet::<Role>::new();

    let my_role = session.my_role();

    for (role_pi, bcast_value) in bcast_data {
        if role_pi != &my_role {
            let sharing_from_sender = &bcast_value.checks_for_mine;
            //Make sure the current sender has sent a value to check against for all parties
            if sharing_from_sender.keys().collect::<HashSet<&Role>>()
                != session
                    .role_assignments()
                    .keys()
                    .collect::<HashSet<&Role>>()
            {
                newly_corrupt.insert(*role_pi);
                tracing::warn!("[{my_role}] Party {role_pi} did not send a check value for all parties, adding it to the corrupt set");
                continue;
            }

            //Check parties in dispute with pi have shares = 0  - Step (g)
            //This should never fail, if there is no dispute the set is empty but exists
            let parties_dispute_pi = session.disputed_roles().get(role_pi)?;
            for pj_dispute_pi in parties_dispute_pi {
                //Add pi to corrupt if sharing from pi to pj is not zero
                if sharing_from_sender
                    .get(pj_dispute_pi)
                    //This should never fail due to the above check
                    .ok_or_else(|| {
                        anyhow_error_and_log(format!(
                            "[{my_role}] Can not find the share for {pj_dispute_pi}"
                        ))
                    })?
                    != &Z::ZERO
                {
                    newly_corrupt.insert(*role_pi);
                    tracing::warn!("[{my_role}] Expected to find a 0 share for {pj_dispute_pi} from {role_pi} due to dispute, but did not. Adding {role_pi} it to corrupt");
                    break;
                }
            }
            if !newly_corrupt.contains(role_pi) {
                //Check correct degree
                let sharing = sharing_from_sender
                    .iter()
                    .map(|(role, share)| Share::new(*role, *share))
                    .collect_vec();
                let sharing = ShamirSharings::create(sharing);
                let try_reconstruct = sharing.err_reconstruct(threshold, 0);

                if let Ok(value) = try_reconstruct {
                    if let Some(result_map) = result_map {
                        result_map.insert(*role_pi, value);
                    }
                } else {
                    tracing::warn!(
                        "[{my_role}] Reconstruction from {role_pi} failed, adding it to corrupt. {:?}",
                        try_reconstruct
                    );
                    newly_corrupt.insert(*role_pi);
                }
            }
        }
    }

    Ok(newly_corrupt)
}

/// Add party to dispute based on the challenges in bcast_data
/// returns true if no new dispute appeared, false else
pub(crate) fn look_for_disputes<Z: Ring, L: LargeSessionHandles>(
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
    use super::{Derive, LocalSingleShare, SecureLocalSingleShare};
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z128;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z64;
    use crate::algebra::structure_traits::{ErrorCorrect, Invert, RingEmbed};
    use crate::execution::sharing::shamir::RevealOp;
    #[cfg(feature = "slow_tests")]
    use crate::execution::{
        communication::broadcast::{Broadcast, SyncReliableBroadcast},
        large_execution::{
            coinflip::{Coinflip, RealCoinflip, SecureCoinflip},
            local_single_share::RealLocalSingleShare,
            share_dispute::{RealShareDispute, ShareDispute},
            vss::{RealVss, SecureVss, Vss},
        },
        sharing::open::{RobustOpen, SecureRobustOpen},
    };
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
    use crate::networking::NetworkMode;
    use crate::{
        execution::{
            runtime::party::Role,
            runtime::session::{
                BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
            },
            sharing::{shamir::ShamirSharings, share::Share},
        },
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, TestingParameters,
        },
    };

    use crate::algebra::structure_traits::Ring;
    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rstest::rstest;

    fn test_lsl_strategies<
        Z: Ring + RingEmbed + Derive + Invert + ErrorCorrect,
        const EXTENSION_DEGREE: usize,
        L: LocalSingleShare + 'static,
    >(
        params: TestingParameters,
        malicious_lsl: L,
    ) {
        let num_secrets = 10_usize;

        let (_, malicious_due_to_dispute) = params.get_dispute_map();

        let mut task_honest = |mut session: LargeSession| async move {
            let real_lsl = SecureLocalSingleShare::default();
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role(),
                real_lsl.execute(&mut session, &secrets).await.unwrap(),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_lsl: L| async move {
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role(),
                malicious_lsl.execute(&mut session, &secrets).await,
            )
        };

        // LocalSingleShare assumes Sync network
        let (result_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.dispute_pairs,
                &[
                    malicious_due_to_dispute.clone(),
                    params.malicious_roles.to_vec(),
                ]
                .concat(),
                malicious_lsl,
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
        //For others we expect the real value
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
                let mut vec_shares = Vec::new();
                for (role, result_lsl, _, _) in result_honest.iter() {
                    vec_shares.push(Share::new(
                        *role,
                        result_lsl.get(&sender_role).unwrap()[secret_id],
                    ));
                }
                let shamir_sharing = ShamirSharings::create(vec_shares);
                let result = shamir_sharing.reconstruct(params.threshold);
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), expected_secret);
            }
        }
    }

    // Rounds (happy path)
    //      share dispute = 1 round
    //      pads =  1 round // note that we could merge this round into the first one. This is currently discussed in the NIST doc
    //      coinflip = vss + open = (1 + 3 + t) + 1
    //      verify = m reliable_broadcast = m*(3 + t) rounds
    // with m = div_ceil(DISPUTE_STAT_SEC,Z::LOG_SIZE_EXCEPTIONAL_SET) (=20 for ResiduePolyF4)
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(88)))]
    #[case(TestingParameters::init_honest(7, 2, Some(109)))]
    fn test_lsl_z128(#[case] params: TestingParameters) {
        let malicious_lsl = SecureLocalSingleShare::default();
        test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
        test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_lsl_malicious_subprotocols_caught<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0,3],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,5,6],&[],true,None)
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
            RealCoinflip::new(_vss_strategy.clone(), _robust_open_strategy.clone()),
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
        let malicious_lsl = RealLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        };
        test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
        test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_lsl_malicious_subprotocols_not_caught<
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
        let malicious_lsl = RealLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        };

        test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
        test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[2],&[0],&[],true,None), SecureCoinflip::default(), MaliciousShareDisputeRecons::new(&params.roles_to_lie_to), SyncReliableBroadcast::default())]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],false,None), MaliciousCoinflipRecons::<SecureVss,SecureRobustOpen>::default(), RealShareDispute::default(), SyncReliableBroadcast::default())]
    #[cfg(feature = "slow_tests")]
    fn test_lsl_malicious_subprotocols_fine_grain<
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
    >(
        #[case] params: TestingParameters,
        #[case] coinflip_strategy: C,
        #[case] share_dispute_strategy: S,
        #[case] broadcast_strategy: BCast,
    ) {
        let malicious_lsl = RealLocalSingleShare {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
        };
        test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
        test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
    }

    //Tests for when some parties lie about shares they received
    //Parties should finish after second iteration,
    //catching malicious users only if it lies about too many parties
    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_malicious_receiver_lsl_malicious_subprotocols<
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
            TestingParameters::init(7,2,&[1,4],&[0,2,6],&[],true,None)
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
        use crate::malicious_execution::large_execution::malicious_local_single_share::MaliciousReceiverLocalSingleShare;

        let malicious_lsl = MaliciousReceiverLocalSingleShare::new(
            coinflip_strategy,
            share_dispute_strategy,
            broadcast_strategy,
            &params.roles_to_lie_to,
        );
        test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
        test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
    }

    //Tests for when some parties lie about shares they sent
    //Parties should finish after second iteration, catching malicious sender always because it keeps lying
    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_malicious_sender_lsl_malicious_subprotocols<
        V: Vss,
        C: Coinflip + 'static,
        S: ShareDispute + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
            TestingParameters::init(4,1,&[2],&[0],&[],true,None),
            TestingParameters::init(4,1,&[2],&[0,1],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,6],&[],true,None),
            TestingParameters::init(7,2,&[1,4],&[0,2,3,6],&[],true,None)
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
        use crate::malicious_execution::large_execution::malicious_local_single_share::MaliciousSenderLocalSingleShare;

        let malicious_lsl = MaliciousSenderLocalSingleShare::new(
            coinflip_strategy,
            share_dispute_strategy,
            broadcast_strategy,
            &params.roles_to_lie_to,
        );

        test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
        test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_lsl.clone(),
        );
    }
}
