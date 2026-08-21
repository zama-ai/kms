use super::{
    coinflip::{Coinflip, SecureCoinflip},
    constants::DISPUTE_STAT_SEC,
    share_dispute::{
        SecureShareDispute, ShareDispute, ShareDisputeOutput, split_share_dispute_output,
    },
};
use crate::{
    network_value::BroadcastValue,
    {
        communication::broadcast::{Broadcast, SyncReliableBroadcast},
        runtime::sessions::large_session::LargeSessionHandles,
    },
};
use algebra::{
    sharing::{
        shamir::{RevealOp, ShamirSharings},
        share::Share,
    },
    structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingWithExceptionalSequence},
};
use async_trait::async_trait;
use error_utils::anyhow_error_and_log;
use itertools::Itertools;
use num_integer::div_ceil;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use thread_handles::spawn_compute_bound;
use threshold_types::protocol::ProtocolDescription;
use threshold_types::role::Role;
use tracing::instrument;

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
    async fn execute<
        Z: RingWithExceptionalSequence + Invert + Derive + ErrorCorrect,
        L: LargeSessionHandles,
    >(
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
        let indent = Self::INDENT_STRING.repeat(depth);
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
    #[instrument(name="LocalSingleShare",skip(self,session,secrets),fields(sid = ?session.session_id(),my_role=?session.my_role(),batch_size = ?secrets.len()))]
    async fn execute<
        Z: RingWithExceptionalSequence + Invert + Derive + ErrorCorrect,
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

        // NOTE TO REVIEWER: For some reason it seems we want to explicitly bound this loop
        // although theory tells us it's bound to finish. But the bound we had was very optimistic.
        //
        // Each iteration adds at least one dispute pair
        // After a party is in dispute with (strictly) more than threshold
        // parties, it is declared corrupt, and we can have at most t corrupt parties
        // Worst case we thus have t * (t+1) dispute-driven restarts and t corrupt driven restarts
        // (Note: Maybe not tight)
        // so we can have at most t * (t + 2) + 1 iterations
        let max_iter = session.threshold() * (session.threshold() + 2) + 1;
        // Implements LocalSingleShare (spec Fig. 88); the //Step N.x comments below reference
        // that figure.
        //
        // Keeps executing until verification passes, excluding malicious players every time it
        // does not. Re-entering this outer loop is the spec's "return to step 1 for all parallel
        // executions" (Steps 5, 6.f, 6.g and 6.h). Step 1 itself (a corrupt dealer contributes
        // the all-zero sharing) is realized on the receiver side: ShareDispute hands out zero
        // shares for corrupt/disputed dealers, and verify_sharing zero-fills the output of any
        // sender that becomes corrupt.
        for _ in 0..max_iter {
            let mut shared_secrets;
            let mut x;
            let mut shared_pads;

            // The following loop is guaranteed to terminate.
            // We we will leave it once the corrupt set does not change.
            // This happens right away on the happy path or worst case after all parties are in there and no new parties can be added.
            loop {
                let corrupt_start = session.corrupt_roles().clone();

                //Step 2 & Step 3: share the secrets <s_j> and the m pads <r_g> via ShareDispute,
                //merged into a single round.
                //ShareDispute will fill shares from disputed parties with 0s.
                (shared_secrets, shared_pads) =
                    share_secrets_and_pads(session, &self.share_dispute, secrets).await?;

                //Step 4: x <- CoinFlip(Corrupt); a single coinflip shared by all n parallel dealers
                x = self.coinflip.execute(session).await?;

                //Step 5: if Corrupt grew (during ShareDispute or the coinflip), start from the
                //top so ShareDispute is consistent with the new Corrupt (and Dispute) sets;
                //otherwise exit the loop and move on
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }

            //Step 6: the m-fold checked opening (see verify_sharing for Steps 6.a-6.h)
            if verify_sharing(
                session,
                &mut shared_secrets,
                shared_pads,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                //Step 7: return the (verified) degree-t sharings of every dealer
                return Ok(shared_secrets.all_shares);
            }
        }
        Err(anyhow_error_and_log(
            "Failed to verify sharing after {max_iter} iterations for `RealLocalSingleShare`",
        ))
    }
}

/// Fig. 88 Steps 2 & 3: sample the `m` pads and share `secrets ‖ pads` in a single
/// [`ShareDispute`] round, then split the output back into the `(secrets, pads)`
/// [`ShareDisputeOutput`]s.
///
/// Merging the two sharings (the spec's <s> and <r>) saves one communication round.
/// Note the pads are sampled *before* ShareDispute samples its sharing polynomials, so the
/// RNG consumption order differs from sharing secrets and pads separately (KATs move).
pub(crate) async fn share_secrets_and_pads<Z, L, S>(
    session: &mut L,
    share_dispute: &S,
    secrets: &[Z],
) -> anyhow::Result<(ShareDisputeOutput<Z>, ShareDisputeOutput<Z>)>
where
    Z: RingWithExceptionalSequence + Derive + Invert,
    L: LargeSessionHandles,
    S: ShareDispute,
{
    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let my_pads = (0..m).map(|_| Z::sample(session.rng())).collect_vec();
    let secrets_and_pads = [secrets, my_pads.as_slice()].concat();
    let merged = share_dispute.execute(session, &secrets_and_pads).await?;
    Ok(split_share_dispute_output(merged, secrets.len()))
}

/// Fig. 88 Step 6: the m-fold checked opening, verifying every dealer's batch at once.
/// Sub-steps 6.a-6.h are annotated inline; all m challenge indices ride a single broadcast.
pub(crate) async fn verify_sharing<
    Z: Ring + Derive + ErrorCorrect,
    L: LargeSessionHandles,
    BCast: Broadcast,
>(
    session: &mut L,
    secrets: &mut ShareDisputeOutput<Z>,
    pads: ShareDisputeOutput<Z>,
    x: &Z,
    l: usize,
    broadcast: &BCast,
) -> anyhow::Result<bool> {
    let (secrets_shares_all, my_shared_secrets) =
        (&mut secrets.all_shares, &mut secrets.shares_own_secret);
    // `pads` is read-only and unused after this call, so take it by value and move its maps into
    // the build task below (no clone).
    let ShareDisputeOutput {
        all_shares: pads_shares_all,
        shares_own_secret: my_shared_pads,
    } = pads;
    let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
    let my_role = session.my_role();

    // The `x` fixing the challenges was drawn by the coinflip *before* this call, so the m
    // check-value maps are independent of one another: we compute them all locally, then
    // broadcast them together in a single parallel round (spec Fig. 88), instead of one
    // broadcast per `g`.
    //
    // Building the batch is a pure CPU burst over `m` independent challenge indices. We run the
    // fan-out on the dedicated MPC rayon pool via `spawn_compute_bound`, so the tokio worker
    // stays free (rather than blocking on an inline `par_iter`). The `pads` maps are moved in;
    // the `secrets` maps are cloned because they are mutated (corrupt senders zeroed) and
    // returned after this call. The burst runs before this call touches the network.
    let my_batch: Vec<MapsSharesChallenges<Z>> = {
        let roles = session.roles().clone();
        let secrets_shares_all = secrets_shares_all.clone();
        let my_shared_secrets = my_shared_secrets.clone();
        let x = *x;
        spawn_compute_bound(move || {
            (0..m)
                .into_par_iter()
                .map(|g| -> anyhow::Result<MapsSharesChallenges<Z>> {
                    //Step 6.a: (x_{1,g},..,x_{l,g}) = H_LDS(x, g, i); one challenge vector per dealer i
                    let map_challenges =
                        Z::derive_challenges_from_coinflip(&x, g.try_into()?, l, &roles);

                    //Step 6.b: my share of <y_g> = <r_g> + sum_j x_{j,g}*<s_j> for every dealer's
                    //local single share happening in parallel
                    let checks_for_all = compute_check_values(
                        &pads_shares_all,
                        &map_challenges,
                        &secrets_shares_all,
                        g,
                        None,
                    )?;

                    //Step 6.c: the full claimed sharing <y_g^*>_j (all j) of MY OWN check value,
                    //computed from the values remembered when dealing ShareDispute
                    let checks_for_mine = compute_check_values(
                        &my_shared_pads,
                        &map_challenges,
                        &my_shared_secrets,
                        g,
                        Some(&my_role),
                    )?;

                    Ok(MapsSharesChallenges {
                        checks_for_all,
                        checks_for_mine,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .await??
    };

    let corrupt_before_bc = session.corrupt_roles().clone();

    //Steps 6.d & 6.e in one batched round: as receiver I broadcast my Step-6.b shares for every
    //dealer (6.d), and as dealer I broadcast my full Step-6.c claimed sharing (6.e) - for all m
    //challenge indices at once, via the Corrupt-set-updating broadcast (spec Fig. 71).
    //All roles will be mapped to an output, but it may be Bot if they are malicious
    let bcast_data = broadcast
        .broadcast_from_all_w_corrupt_set_update(
            session,
            BroadcastValue::LocalSingleShare(my_batch),
        )
        .await?;

    //Step 6.f: if any of the broadcasts increased Corrupt, return to Step 1
    if *session.corrupt_roles() != corrupt_before_bc {
        return Ok(false);
    }

    //Reshape the (owned) broadcast into one map per challenge index `g`, moving each sender's
    //`MapsSharesChallenges` out of its batch (no clone). Each per-`g` map is wrapped in an `Arc`
    //so it can be shared cheaply between the reconstruction compute task and `look_for_disputes`.
    //Senders that did not broadcast a batch of the expected length `m` are marked corrupt
    //(treated like a Bot broadcast, i.e. the Fig. 71 convention).
    let mut per_g: Vec<HashMap<Role, MapsSharesChallenges<Z>>> =
        (0..m).map(|_| HashMap::new()).collect();
    let mut wrong_type_corrupts = HashSet::new();
    for (role, bcast_value) in bcast_data {
        match bcast_value {
            BroadcastValue::LocalSingleShare(batch) if batch.len() == m => {
                for (g, maps) in batch.into_iter().enumerate() {
                    per_g[g].insert(role, maps);
                }
            }
            _ => {
                wrong_type_corrupts.insert(role);
            }
        }
    }
    let per_g: Vec<Arc<HashMap<Role, MapsSharesChallenges<Z>>>> =
        per_g.into_iter().map(Arc::new).collect();

    //Compute the per-sender verdicts (the Step 6.g checks) for all m challenge indices in one
    //compute task. The verdicts are pure functions of
    //the broadcast data and the start-of-pass `VerifyCtx` snapshot, so precomputing the later
    //indices is safe: the decision loop below restarts the protocol on the first index that
    //changes the corrupt or dispute set, hence any verdict actually consumed was computed
    //against exactly the session state a sequential computation would have observed.
    let threshold = session.threshold() as usize;
    let verdicts = {
        let ctx = VerifyCtx::new(session);
        let per_g = per_g.clone(); // one Arc bump per challenge index
        spawn_compute_bound(move || {
            per_g
                .par_iter()
                .map(|bcast_g| sender_verdicts(bcast_g, &ctx, threshold))
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .await??
    };

    //Sequentially apply each challenge index's outcome against the single broadcast.
    //Restarting (Ok(false)) on the FIRST index that reveals a new corrupt party or dispute is
    //load-bearing, not an optimization: a later index's dispute-zero checks would otherwise
    //judge sharings created under the old dispute set against the new one, marking honest
    //dealers corrupt.
    for (g, (bcast_output, g_verdicts)) in per_g.iter().zip(verdicts.iter()).enumerate() {
        //`None` verdicts are the newly-corrupt senders; the reconstructed check values are
        //not needed for the single sharing.
        let (mut bcast_corrupts, _) = split_verdicts(g_verdicts);
        //Wrong-type senders are corrupt across every challenge index; fold them in on the first pass.
        if g == 0 {
            bcast_corrupts.extend(wrong_type_corrupts.iter().cloned());
        }

        //Step 6.g (application): add failing dealers to Corrupt and set their sharings to the
        //all-zero sharing (the Step 1 convention for corrupt dealers)
        let mut should_return = false;
        for role_pi in bcast_corrupts {
            secrets_shares_all.insert(role_pi, vec![Z::ZERO; l]);
            should_return |= session.add_corrupt(role_pi);
        }

        //Step 6.h: compare receivers' broadcast shares against each dealer's claimed sharing;
        //any new dispute - or a new corrupt party from Step 6.g - returns to Step 1
        if should_return || !look_for_disputes(bcast_output, session)? {
            tracing::warn!(
                "RESTARTING LocalSingleShare as we detected a new dispute or corrupt party"
            );
            return Ok(false);
        }
    }

    //If we reached here, everything went fine
    Ok(true)
}

// The linear combination of Fig. 88 Step 6.b / Fig. 89 Step 7.b - and of Step 6.c / 7.c when
// `my_role` is set (it then evaluates the dealer's own remembered shares for every receiver).
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
            if vec_challenges.len() != vec_secret_shares.len() {
                return Err(anyhow_error_and_log(
                    "Inconsistent vector lengths".to_string(),
                ));
            }
            Ok((
                *role,
                pads_shares[g]
                    + vec_challenges
                        .iter()
                        .zip_eq(vec_secret_shares.iter())
                        .fold(Z::ZERO, |acc, (x, s)| acc + *x * *s),
            ))
        })
        .try_collect()
}

/// Start-of-pass snapshot of the session state read by [`sender_verdicts`]: our role, the
/// full role set, and each other party's dispute set as they stood when the verification
/// pass began.
///
/// One snapshot is shared by the verdict computation for every challenge index. This is
/// sound because the per-`g` decision loop restarts the whole protocol (`Ok(false)`) on the
/// first index that adds a corrupt party or a dispute: any execution that actually consumes
/// index `g`'s verdicts has applied no session mutation since the pass began, so the
/// snapshot is exactly the state a per-`g` computation would have observed.
pub(crate) struct VerifyCtx {
    pub(crate) my_role: Role,
    pub(crate) roles: HashSet<Role>,
    pub(crate) sender_disputes: HashMap<Role, BTreeSet<Role>>,
}

impl VerifyCtx {
    /// Snapshot the session at the start of a verification pass.
    pub(crate) fn new<L: LargeSessionHandles>(session: &L) -> Self {
        let my_role = session.my_role();
        Self {
            my_role,
            roles: session.roles().clone(),
            sender_disputes: session
                .roles()
                .iter()
                .filter(|role| **role != my_role)
                .map(|role| (*role, session.disputed_roles().get(role).clone()))
                .collect(),
        }
    }
}

/// Fig. 88 Step 6.g / Fig. 89 Step 7.g: verify that each sender did give a 0 share to parties
/// it is in dispute with and that its claimed check-value sharing is a degree-`threshold`
/// polynomial. Maps every sender in `bcast_g` (other than ourselves) to `Some(reconstructed
/// check value)` if the sharing is valid, or to `None`, which proves the sender corrupt.
///
/// This is a pure function of the broadcast data and the start-of-pass [`VerifyCtx`]
/// snapshot — no session access — so callers can compute the verdicts for *all* `m`
/// challenge indices (and, for the double sharing, both degrees) in a single
/// `spawn_compute_bound` task before the sequential per-`g` decision loop runs. The
/// per-sender work (dominated by the error-correcting `error_reconstruct` decode) fans out
/// across rayon; the caller merges verdicts sequentially via [`split_verdicts`], so the
/// outcome is identical to processing senders (and indices) one by one.
pub(crate) fn sender_verdicts<Z: Ring + ErrorCorrect>(
    bcast_g: &HashMap<Role, MapsSharesChallenges<Z>>,
    ctx: &VerifyCtx,
    threshold: usize,
) -> anyhow::Result<Vec<(Role, Option<Z>)>> {
    let my_role = ctx.my_role;
    bcast_g
        .par_iter()
        .filter(|(role_pi, _)| **role_pi != my_role)
        .map(|(role_pi, bcast_value)| -> anyhow::Result<(Role, Option<Z>)> {
            let sharing_from_sender = &bcast_value.checks_for_mine;
            //Well-formedness of Step 6.e/7.e: the dealer must have broadcast a claimed share
            //for every party, otherwise it is corrupt
            if sharing_from_sender
                .keys()
                .cloned()
                .collect::<HashSet<Role>>()
                != ctx.roles
            {
                tracing::warn!(
                    "[{my_role}] Party {role_pi} did not send a check value for all parties, adding it to the corrupt set"
                );
                return Ok((*role_pi, None));
            }

            //Step 6.g/7.g (zero condition): parties in dispute with pi must hold the zero share
            //This should never fail, if there is no dispute the set is empty but exists
            if let Some(pi_disputes) = ctx.sender_disputes.get(role_pi) {
                for pj_dispute_pi in pi_disputes {
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
                        tracing::warn!(
                            "[{my_role}] Expected to find a 0 share for {pj_dispute_pi} from {role_pi} due to dispute, but did not. Adding {role_pi} it to corrupt"
                        );
                        return Ok((*role_pi, None));
                    }
                }
            }

            //Step 6.g/7.g (degree condition): the claimed sharing must be a valid
            //degree-`threshold` polynomial; the reconstructed value feeds Fig. 89
            //Step 7.g's t/2t equality check
            let sharing = sharing_from_sender
                .iter()
                .map(|(role, share)| Share::new(*role, *share))
                .collect_vec();
            let sharing = ShamirSharings::create(sharing);
            match sharing.error_reconstruct(threshold, 0) {
                Ok(value) => Ok((*role_pi, Some(value))),
                Err(e) => {
                    tracing::warn!(
                        "[{my_role}] Reconstruction from {role_pi} failed, adding it to corrupt. {:?}",
                        e
                    );
                    Ok((*role_pi, None))
                }
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

/// The sequential-merge half of the per-sender verification: split one challenge index's
/// verdicts into the newly-corrupt senders (`None` verdicts) and the reconstructed check
/// values of the valid ones.
pub(crate) fn split_verdicts<Z: Ring>(
    verdicts: &[(Role, Option<Z>)],
) -> (HashSet<Role>, HashMap<Role, Z>) {
    let mut newly_corrupt = HashSet::new();
    let mut result_map = HashMap::new();
    for (role_pi, verdict) in verdicts {
        match verdict {
            //Corrupt sender
            None => {
                newly_corrupt.insert(*role_pi);
            }
            //Valid sharing: record the reconstructed check value
            Some(value) => {
                result_map.insert(*role_pi, *value);
            }
        }
    }
    (newly_corrupt, result_map)
}

/// Fig. 88 Step 6.h / Fig. 89 Step 7.h: add a dispute {sender, receiver} for every receiver in
/// Agree_i whose broadcast share (Step 6.d/7.d) disagrees with the dealer's claimed share for
/// it (Step 6.e/7.e).
/// Returns true if no new dispute appeared, false else
pub(crate) fn look_for_disputes<Z: Ring, L: LargeSessionHandles>(
    bcast_data: &HashMap<Role, MapsSharesChallenges<Z>>,
    session: &mut L,
) -> anyhow::Result<bool> {
    let mut everything_ok = true;

    for (role_sender, bcast_value) in bcast_data {
        if !session.corrupt_roles().contains(role_sender) {
            //This should never fail, if there is no dispute the set is empty but exists
            let sender_dispute_set = session.disputed_roles().get(role_sender).clone();
            //Senders that have wrong type are already in the corrupt set from before, so no need for an else clause
            let sender_vote = &bcast_value.checks_for_mine;
            //Similarly, we know that sender maps all the parties to something from before
            for (role_receiver, sender_value) in sender_vote {
                //Agree_i restriction of Step 6.h/7.h: receivers in dispute with the sender are
                //"defined" to broadcast 0 (Step 6.d/7.d convention) - the matching dealer-side
                //zero was checked in [sender_verdicts] - so they are skipped here.
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

                    //Step 6.h/7.h: <y_g>_j != <y_g^*>_j => add {pi, pj} to Dispute
                    match receiver_value {
                        Some(rcv_value) if *rcv_value == sender_value => {}
                        _ => {
                            tracing::warn!(
                                "Parties {role_receiver} and Sender {role_sender} disagree on the checking value. Add a dispute"
                            );
                            session.add_dispute(role_receiver, role_sender);
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
    use super::RealLocalSingleShare;
    use super::{Derive, LocalSingleShare, SecureLocalSingleShare};
    #[cfg(feature = "slow_tests")]
    use crate::large_execution::{coinflip::SecureCoinflip, vss::SecureVss};
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
    use crate::runtime::sessions::large_session::{LargeSession, LargeSessionHandles};
    use crate::tests::helper::tests::{
        TestingParameters, execute_protocol_large_w_disputes_and_malicious,
    };
    use crate::{
        communication::broadcast::{Broadcast, SyncReliableBroadcast},
        large_execution::{
            coinflip::{Coinflip, RealCoinflip},
            share_dispute::{RealShareDispute, ShareDispute},
            vss::{RealVss, Vss},
        },
        sharing::open::{RobustOpen, SecureRobustOpen},
    };
    use algebra::{
        galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        sharing::{
            shamir::{RevealOp, ShamirSharings},
            share::Share,
        },
        structure_traits::{ErrorCorrect, Invert, Ring},
    };
    use threshold_types::network::NetworkMode;

    use aes_prng::AesRng;
    use futures_util::future::join;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::collections::HashSet;
    use threshold_types::role::Role;

    async fn test_lsl_strategies<
        Z: Derive + Invert + ErrorCorrect,
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
                real_lsl.execute(&mut session, &secrets).await.unwrap(),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_lsl: L| async move {
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();

            malicious_lsl.execute(&mut session, &secrets).await
        };

        let mut malicious_roles_with_dispute = HashSet::from_iter(malicious_due_to_dispute);
        malicious_roles_with_dispute.extend(params.malicious_roles.clone());

        // LocalSingleShare assumes Sync network
        let (result_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.dispute_pairs,
                &malicious_roles_with_dispute,
                malicious_lsl,
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
            assert_eq!(*malicious_set, ref_malicious_set);
            assert_eq!(*dispute_set, ref_dispute_set);
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
                for (role, (result_lsl, _, _)) in result_honest.iter() {
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
    //      share dispute = 1 round (secrets and pads shared together)
    //      coinflip = vss + open = (1 + 3 + t) + 1
    //      verify = 1 reliable_broadcast = (3 + t) rounds
    //          (the m check-value maps are batched into a single broadcast)
    // 4p/1t: 1 + (1 + 3 + 1) + 1 + (3 + 1) = 11
    // 7p/2t: 1 + (1 + 3 + 2) + 1 + (3 + 2) = 13
    #[tokio::test]
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(11)))]
    #[case(TestingParameters::init_honest(7, 2, Some(13)))]
    async fn test_lsl_z128(#[case] params: TestingParameters) {
        let malicious_lsl = SecureLocalSingleShare::default();
        join(
            test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
            test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[rstest]
    async fn test_lsl_malicious_subprotocols_caught<
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
        join(
            test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
            test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
        )
        .await;
    }

    #[tokio::test]
    #[rstest]
    async fn test_lsl_malicious_subprotocols_not_caught<
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

        join(
            test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
            test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
        )
        .await;
    }

    #[tokio::test]
    #[rstest]
    #[case(TestingParameters::init(4,1,&[2],&[0],&[],true,None), SecureCoinflip::default(), MaliciousShareDisputeRecons::new(&params.roles_to_lie_to), SyncReliableBroadcast::default())]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],false,None), MaliciousCoinflipRecons::<SecureVss,SecureRobustOpen>::default(), RealShareDispute::default(), SyncReliableBroadcast::default())]
    #[cfg(feature = "slow_tests")]
    async fn test_lsl_malicious_subprotocols_fine_grain<
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
        join(
            test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
            test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
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
    async fn test_malicious_receiver_lsl_malicious_subprotocols<
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
        join(
            test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
            test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
        )
        .await;
    }

    //Tests for when some parties lie about shares they sent
    //Parties should finish after second iteration, catching malicious sender always because it keeps lying
    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[rstest]
    async fn test_malicious_sender_lsl_malicious_subprotocols<
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

        join(
            test_lsl_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
            test_lsl_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
                params.clone(),
                malicious_lsl.clone(),
            ),
        )
        .await;
    }
}
