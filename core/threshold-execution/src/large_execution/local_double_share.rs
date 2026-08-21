use super::{
    coinflip::{Coinflip, SecureCoinflip},
    constants::DISPUTE_STAT_SEC,
    local_single_share::{
        MapsSharesChallenges, VerifyCtx, compute_check_values, look_for_disputes, sender_verdicts,
        split_verdicts,
    },
    share_dispute::{
        SecureShareDispute, ShareDispute, ShareDisputeOutput, ShareDisputeOutputDouble,
        split_share_dispute_output_double,
    },
};
use crate::network_value::BroadcastValue;
use crate::{
    communication::broadcast::{Broadcast, SyncReliableBroadcast},
    runtime::sessions::large_session::LargeSessionHandles,
};
use algebra::structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingWithExceptionalSequence};
use async_trait::async_trait;
use error_utils::anyhow_error_and_log;
use itertools::Itertools;
use num_integer::div_ceil;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use thread_handles::spawn_compute_bound;
use threshold_types::protocol::ProtocolDescription;
use threshold_types::role::Role;
use tracing::instrument;

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
        let indent = Self::INDENT_STRING.repeat(depth);
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

        // Each iteration adds at least one dispute pair
        // After a party is in dispute with (strictly) more than threshold
        // parties, it is declared corrupt, and we can have at most t corrupt parties
        // Worst case we thus have t * (t+1) dispute-driven restarts and t corrupt driven restarts
        // (Note: Maybe not tight)
        // so we can have at most t * (t + 2) + 1 iterations
        let max_iter = session.threshold() * (session.threshold() + 2) + 1;
        // Implements LocalDoubleShare (spec Fig. 89); the //Step N.x comments below reference
        // that figure.
        //
        // Keeps executing til verification passes. Re-entering this outer loop is the spec's
        // "return to step 1 for all parallel executions" (Steps 6, 7.f, 7.g and 7.h). Step 1
        // itself (a corrupt dealer contributes all-zero sharings) is realized on the receiver
        // side, as in LocalSingleShare.
        for _ in 0..max_iter {
            let mut shared_secrets_double;
            let mut x;
            let mut shared_pads_double;

            loop {
                let corrupt_start = session.corrupt_roles().clone();

                //Steps 2, 3 & 4: share the secrets <s_j> at degrees t (Step 2) and 2t (Step 3)
                //together with the m pads <r_g> at both degrees (Step 4), all in a single
                //ShareDispute round (the spec's round accounting already counts these as one
                //round). ShareDispute will fill shares from disputed parties with 0s.
                (shared_secrets_double, shared_pads_double) =
                    share_secrets_and_pads_double(session, &self.share_dispute, secrets).await?;

                //Step 5: x <- CoinFlip(Corrupt); a single coinflip shared by all n parallel dealers
                x = self.coinflip.execute(session).await?;

                //Step 6: if Corrupt grew (during ShareDispute or the coinflip), start from the
                //top so ShareDispute is consistent with the new Corrupt (and Dispute) sets;
                //otherwise exit the loop and move on
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }

            //Step 7: the m-fold checked opening (see verify_sharing for Steps 7.a-7.h)
            if verify_sharing(
                session,
                &mut shared_secrets_double,
                shared_pads_double,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                //Step 8: return the (verified) (t, 2t) sharings of every dealer
                return format_output(shared_secrets_double);
            }
        }
        Err(anyhow_error_and_log(
            "Failed to verify sharing after {max_iter} iterations for `RealLocalDoubleShare`",
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

/// Fig. 89 Steps 2, 3 & 4: sample the `m` pads and share `secrets ‖ pads` - each at degrees t
/// and 2t - in a single [`ShareDispute::execute_double`] round, then split the output back
/// into the `(secrets, pads)` [`ShareDisputeOutputDouble`]s.
///
/// Merging the two sharings saves one communication round. As in the single-sharing case, the
/// pads are sampled before ShareDispute samples its polynomials, so the RNG order differs from
/// sharing secrets and pads separately (KATs move).
pub(crate) async fn share_secrets_and_pads_double<Z, L, S>(
    session: &mut L,
    share_dispute: &S,
    secrets: &[Z],
) -> anyhow::Result<(ShareDisputeOutputDouble<Z>, ShareDisputeOutputDouble<Z>)>
where
    Z: RingWithExceptionalSequence + Derive + Invert,
    L: LargeSessionHandles,
    S: ShareDispute,
{
    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let my_pads = (0..m).map(|_| Z::sample(session.rng())).collect_vec();
    let secrets_and_pads = [secrets, my_pads.as_slice()].concat();
    let merged = share_dispute
        .execute_double(session, &secrets_and_pads)
        .await?;
    Ok(split_share_dispute_output_double(merged, secrets.len()))
}

/// Fig. 89 Step 7: the m-fold checked opening, verifying every dealer's (t, 2t) batch at once.
/// Sub-steps 7.a-7.h are annotated inline; all m challenge indices and both degrees ride a
/// single broadcast.
pub(crate) async fn verify_sharing<
    Z: Ring + Derive + ErrorCorrect,
    L: LargeSessionHandles,
    BCast: Broadcast,
>(
    session: &mut L,
    secrets_double: &mut ShareDisputeOutputDouble<Z>,
    pads_double: ShareDisputeOutputDouble<Z>,
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

    // `pads_double` is read-only and unused after this call, so take it by value and move its
    // maps into the build task below (no clone).
    let ShareDisputeOutputDouble {
        output_t:
            ShareDisputeOutput {
                all_shares: pads_shares_all_t,
                shares_own_secret: my_share_pads_t,
            },
        output_2t:
            ShareDisputeOutput {
                all_shares: pads_shares_all_2t,
                shares_own_secret: my_share_pads_2t,
            },
    } = pads_double;

    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let my_role = session.my_role();

    // The `x` fixing the challenges was drawn by the coinflip *before* this call, so the m
    // check-value tuples are independent of one another: we compute them all locally, then
    // broadcast them together in a single parallel round (spec Fig. 88), instead of one
    // broadcast per `g`.
    //
    // Building the batch is a pure CPU burst over `m` independent challenge indices. We run the
    // fan-out on the dedicated MPC rayon pool via `spawn_compute_bound`, so the tokio worker
    // stays free (rather than blocking on an inline `par_iter`). The `pads` maps are moved in;
    // the `secrets` maps are cloned because they are mutated (corrupt senders zeroed) after this
    // call. The burst runs before this call touches the network.
    let my_batch: Vec<MapsDoubleSharesChallenges<Z>> = {
        let roles = session.roles().clone();
        let secrets_shares_all_t = secrets_shares_all_t.clone();
        let secrets_shares_all_2t = secrets_shares_all_2t.clone();
        let my_shared_secrets_t = my_shared_secrets_t.clone();
        let my_shared_secrets_2t = my_shared_secrets_2t.clone();
        let x = *x;
        spawn_compute_bound(move || {
            (0..m)
                .into_par_iter()
                .map(|g| -> anyhow::Result<MapsDoubleSharesChallenges<Z>> {
                    //Step 7.a: (x_{1,g},..,x_{l,g}) = H_LDS(x, g, i); one challenge vector per dealer i
                    let map_challenges =
                        Z::derive_challenges_from_coinflip(&x, g.try_into()?, l, &roles);

                    //Step 7.b (degree t): my share of <y_g> = <r_g> + sum_j x_{j,g}*<s_j> for
                    //every dealer's sharing of degree t
                    let map_share_check_values_t = compute_check_values(
                        &pads_shares_all_t,
                        &map_challenges,
                        &secrets_shares_all_t,
                        g,
                        None,
                    )?;

                    //Step 7.b (degree 2t): my share of <y_g>^{2t} for every dealer's sharing of
                    //degree 2t
                    let map_share_check_values_2t = compute_check_values(
                        &pads_shares_all_2t,
                        &map_challenges,
                        &secrets_shares_all_2t,
                        g,
                        None,
                    )?;

                    //Step 7.c (degree t): the full claimed sharing <y_g^*>_j (all j) of MY OWN
                    //check value, from the values remembered when dealing ShareDispute
                    let map_share_my_check_values_t = compute_check_values(
                        &my_share_pads_t,
                        &map_challenges,
                        &my_shared_secrets_t,
                        g,
                        Some(&my_role),
                    )?;

                    //Step 7.c (degree 2t): the full claimed sharing <y_g^*>_j^{2t} of MY OWN
                    //check value
                    let map_share_my_check_values_2t = compute_check_values(
                        &my_share_pads_2t,
                        &map_challenges,
                        &my_shared_secrets_2t,
                        g,
                        Some(&my_role),
                    )?;

                    Ok((
                        map_share_check_values_t,
                        map_share_check_values_2t,
                        map_share_my_check_values_t,
                        map_share_my_check_values_2t,
                    ))
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .await??
    };

    let corrupt_before_bc = session.corrupt_roles().clone();

    //Steps 7.d & 7.e in one batched round, for every challenge index at once:
    // - 7.d: my Step-7.b shares of every dealer's degree-t and degree-2t check values
    // - 7.e: my full Step-7.c claimed sharings (both degrees) as dealer
    //via the Corrupt-set-updating broadcast (spec Fig. 71).
    let bcast_data = broadcast
        .broadcast_from_all_w_corrupt_set_update(
            session,
            BroadcastValue::LocalDoubleShare(my_batch),
        )
        .await?;

    //Step 7.f: if any of the broadcasts increased Corrupt, return to Step 1
    if *session.corrupt_roles() != corrupt_before_bc {
        return Ok(false);
    }

    //Reshape the (owned) broadcast into one degree-t and one degree-2t map per challenge index
    //`g`, moving each sender's shares out of its batch (no clone). Each per-`g` map is wrapped in
    //an `Arc` so it can be shared cheaply between the reconstruction compute task and
    //`look_for_disputes`. Senders whose batch has the wrong type or length are corrupt
    //(treated like a Bot broadcast, i.e. the Fig. 71 convention).
    let mut per_g_t: Vec<HashMap<Role, MapsSharesChallenges<Z>>> =
        (0..m).map(|_| HashMap::new()).collect();
    let mut per_g_2t: Vec<HashMap<Role, MapsSharesChallenges<Z>>> =
        (0..m).map(|_| HashMap::new()).collect();
    let mut wrong_type_corrupts = HashSet::<Role>::new();
    for (role, map_data) in bcast_data.into_iter() {
        match map_data {
            BroadcastValue::LocalDoubleShare(batch) if batch.len() == m => {
                for (g, (data_share_t, data_share_2t, data_check_t, data_check_2t)) in
                    batch.into_iter().enumerate()
                {
                    per_g_t[g].insert(
                        role,
                        MapsSharesChallenges {
                            checks_for_all: data_share_t,
                            checks_for_mine: data_check_t,
                        },
                    );
                    per_g_2t[g].insert(
                        role,
                        MapsSharesChallenges {
                            checks_for_all: data_share_2t,
                            checks_for_mine: data_check_2t,
                        },
                    );
                }
            }
            _ => {
                //Otherwise, wrong type from sender, mark it corrupt
                tracing::warn!(
                    "Received wrong type from {role} in broadcast, marking it as corrupt"
                );
                wrong_type_corrupts.insert(role);
            }
        }
    }
    let per_g_t: Vec<Arc<HashMap<Role, MapsSharesChallenges<Z>>>> =
        per_g_t.into_iter().map(Arc::new).collect();
    let per_g_2t: Vec<Arc<HashMap<Role, MapsSharesChallenges<Z>>>> =
        per_g_2t.into_iter().map(Arc::new).collect();

    //Compute the per-sender verdicts (the Step 7.g checks, at degree t and 2t) for all m
    //challenge indices AND both degrees in one compute task: the MPC rayon pool sees every
    //`error_reconstruct` decode of the pass at once (2m maps of up to n-1 senders each)
    //instead of 2m sequential bursts with a tokio round-trip in between.
    //Safe for the same reason as the single-sharing variant: the
    //decision loop below restarts on the first index that changes the corrupt/dispute set,
    //so every verdict actually consumed was computed against exactly the session state a
    //per-`g` computation would have observed.
    let threshold_t = session.threshold() as usize;
    let threshold_2t = 2 * threshold_t;
    let (verdicts_t, verdicts_2t) = {
        let ctx = VerifyCtx::new(session);
        let per_g_t = per_g_t.clone(); // one Arc bump per challenge index
        let per_g_2t = per_g_2t.clone();
        spawn_compute_bound(move || {
            let (verdicts_t, verdicts_2t) = rayon::join(
                || {
                    per_g_t
                        .par_iter()
                        .map(|bcast_g| sender_verdicts(bcast_g, &ctx, threshold_t))
                        .collect::<anyhow::Result<Vec<_>>>()
                },
                || {
                    per_g_2t
                        .par_iter()
                        .map(|bcast_g| sender_verdicts(bcast_g, &ctx, threshold_2t))
                        .collect::<anyhow::Result<Vec<_>>>()
                },
            );
            Ok::<_, anyhow::Error>((verdicts_t?, verdicts_2t?))
        })
        .await??
    };

    //Sequentially apply each challenge index's outcome, restarting (Ok(false)) on the FIRST
    //index that reveals a new corrupt party or dispute. The early restart is load-bearing
    //(see the single-sharing variant): a later index's dispute-zero checks must never judge
    //sharings created under the old dispute set against the new one.
    for (g, (bcast_data_t, bcast_data_2t)) in per_g_t.iter().zip(per_g_2t.iter()).enumerate() {
        //`None` verdicts are the newly-corrupt senders; the reconstructed check values feed
        //the t/2t equality check below.
        let (newly_corrupt_t, result_map_t) = split_verdicts(&verdicts_t[g]);
        let (newly_corrupt_2t, result_map_2t) = split_verdicts(&verdicts_2t[g]);

        let mut bcast_corrupts = HashSet::<Role>::new();
        //Wrong-type senders are corrupt across every challenge index; fold them in on the first pass.
        if g == 0 {
            bcast_corrupts.extend(wrong_type_corrupts.iter().cloned());
        }

        //Merge newly_corrupt into a single set
        bcast_corrupts.extend(newly_corrupt_t);
        bcast_corrupts.extend(newly_corrupt_2t);
        //Step 7.g (equality condition): the values reconstructed from the dealer's claimed
        //degree-t and degree-2t sharings must be equal. The dealer's claims are what is
        //compared here; Step 7.h forces those claims to match the receivers' actual broadcast
        //shares.
        //Note that parties which are absent from one result_map or the other are already in newly_corrupt
        for (role, value_t) in result_map_t.iter() {
            if let Some(value_2t) = result_map_2t.get(role)
                && value_2t != value_t
            {
                bcast_corrupts.insert(*role);
            }
        }

        //Step 7.g (application): add failing dealers to Corrupt and set their (t, 2t) sharings
        //to the all-zero sharing (the Step 1 convention for corrupt dealers)
        let mut should_return = false;
        for role_pi in bcast_corrupts {
            secrets_shares_all_t.insert(role_pi, vec![Z::ZERO; l]);
            secrets_shares_all_2t.insert(role_pi, vec![Z::ZERO; l]);
            should_return |= session.add_corrupt(role_pi);
        }
        if should_return {
            return Ok(false);
        }

        //Step 7.h: compare receivers' broadcast shares against each dealer's claimed sharings,
        //at both degrees; any new dispute returns to Step 1
        if (!look_for_disputes(bcast_data_t, session)?)
            || (!look_for_disputes(bcast_data_2t, session)?)
        {
            return Ok(false);
        }
    }

    //If we reached here, evereything went fine
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::communication::broadcast::{Broadcast, SyncReliableBroadcast};
    #[cfg(feature = "slow_tests")]
    use crate::large_execution::{coinflip::SecureCoinflip, vss::SecureVss};
    use crate::large_execution::{
        coinflip::{Coinflip, RealCoinflip},
        local_double_share::RealLocalDoubleShare,
        share_dispute::RealShareDispute,
        share_dispute::ShareDispute,
        vss::{RealVss, Vss},
    };
    #[cfg(feature = "slow_tests")]
    use crate::malicious_execution::large_execution::{
        malicious_coinflip::DroppingCoinflipAfterVss,
        malicious_share_dispute::{
            DroppingShareDispute, MaliciousShareDisputeRecons, WrongShareDisputeRecons,
        },
        malicious_vss::{DroppingVssAfterR1, DroppingVssFromStart},
    };
    use crate::malicious_execution::large_execution::{
        malicious_coinflip::MaliciousCoinflipRecons,
        malicious_vss::{DroppingVssAfterR2, MaliciousVssR1},
    };
    use crate::runtime::sessions::base_session::GenericBaseSessionHandles;
    use crate::sharing::open::{RobustOpen, SecureRobustOpen};

    use crate::tests::helper::tests::{
        TestingParameters, execute_protocol_large_w_disputes_and_malicious,
    };
    use crate::{
        large_execution::local_double_share::{LocalDoubleShare, SecureLocalDoubleShare},
        runtime::sessions::large_session::{LargeSession, LargeSessionHandles},
    };
    use aes_prng::AesRng;
    use threshold_types::network::NetworkMode;

    use algebra::{
        galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        sharing::{
            shamir::{RevealOp, ShamirSharings},
            share::Share,
        },
        structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingWithExceptionalSequence},
    };
    use futures_util::future::join;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::collections::HashSet;
    use threshold_types::role::Role;

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
    //      share dispute = 1 round (secrets and pads shared together)
    //      coinflip = vss + open = (1 + 3 + t) + 1
    //      verify = 1 reliable_broadcast = (3 + t) rounds
    //          (the m check-value tuples are batched into a single broadcast)
    // 4p/1t: 1 + (1 + 3 + 1) + 1 + (3 + 1) = 11
    // 7p/2t: 1 + (1 + 3 + 2) + 1 + (3 + 2) = 13
    #[tokio::test]
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(11)))]
    #[case(TestingParameters::init_honest(7, 2, Some(13)))]
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
    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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
    #[tokio::test]
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
    #[tokio::test]
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
