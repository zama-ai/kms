use std::collections::{BTreeMap, HashMap, HashSet};

use async_trait::async_trait;
use blake3::Hasher;
use itertools::Itertools;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        broadcast::broadcast_with_corruption,
        coinflip::Coinflip,
        large_execution::share_dispute::{ShareDispute, ShareDisputeOutput},
        party::Role,
        session::LargeSessionHandles,
    },
    poly::Ring,
    residue_poly::ResiduePoly,
    value::{err_reconstruct, BroadcastValue, IndexedValue, Value},
    Sample, Zero, Z128,
};

use super::constants::DISPUTE_STAT_SEC;

#[async_trait]
pub trait LocalSingleShare: Send + Default {
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
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<HashMap<Role, Vec<ResiduePoly<Z128>>>>;
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct MapsSharesChallenges {
    pub(crate) checks_for_all: BTreeMap<Role, ResiduePoly<Z128>>,
    pub(crate) checks_for_mine: BTreeMap<Role, ResiduePoly<Z128>>,
}

/// We expect instances of:
/// - [Coinflip]
/// - [ShareDispute]
#[derive(Default)]
pub struct RealLocalSingleShare<C: Coinflip, S: ShareDispute> {
    _marker_coinflip: std::marker::PhantomData<C>,
    _marker_share_dispute: std::marker::PhantomData<S>,
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute> LocalSingleShare for RealLocalSingleShare<C, S> {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<HashMap<Role, Vec<ResiduePoly<Z128>>>> {
        //Keeps executing til verification passes
        loop {
            //ShareDispute will fill shares from corrupted players with 0s
            let mut shared_secrets = S::execute(session, secrets).await?;

            let shared_pads = send_receive_pads::<R, L, S>(session).await?;

            let x = C::execute(session).await?;

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

async fn send_receive_pads<R, L, S>(session: &mut L) -> anyhow::Result<ShareDisputeOutput>
where
    R: RngCore,
    L: LargeSessionHandles<R>,
    S: ShareDispute,
{
    let m = (DISPUTE_STAT_SEC as f64 / ResiduePoly::<Z128>::BIT_LENGTH as f64).ceil() as usize;
    let my_pads: Vec<ResiduePoly<Z128>> = (0..m)
        .map(|_| ResiduePoly::<Z128>::sample(session.rng()))
        .collect();
    S::execute(session, &my_pads).await
}

async fn verify_sharing<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    secrets: &mut ShareDisputeOutput,
    pads: &ShareDisputeOutput,
    x: &ResiduePoly<Z128>,
    l: usize,
) -> anyhow::Result<bool> {
    let (secrets_shares_all, my_shared_secrets) =
        (&mut secrets.all_shares, &mut secrets.shares_own_secret);
    let (pads_shares_all, my_shared_pads) = (&pads.all_shares, &pads.shares_own_secret);
    let m = (DISPUTE_STAT_SEC as f64 / ResiduePoly::<Z128>::BIT_LENGTH as f64).ceil() as usize;
    let roles = session.role_assignments().keys().cloned().collect_vec();
    let my_role = session.my_role()?;
    let mut result = true;
    for g in 0..m {
        let map_challenges = derive_challenges_from_coinflip(x, g, l, &roles);

        //Compute my share of check values for every local single share happening in parallel
        let map_share_check_values: BTreeMap<Role, ResiduePoly<Z128>> = compute_check_values(
            pads_shares_all,
            &map_challenges,
            secrets_shares_all,
            g,
            None,
        )?;

        //Compute the share of the check value for MY local single share
        let map_share_my_check_values: BTreeMap<Role, ResiduePoly<Z128>> = compute_check_values(
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
        let mut bcast_output = HashMap::<Role, MapsSharesChallenges>::new();
        let mut bcast_corrupts = HashSet::<Role>::new();
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
            secrets_shares_all.insert(role_pi, vec![ResiduePoly::<Z128>::ZERO; l]);
            session.add_corrupt(role_pi)?;
        }

        result &= look_for_disputes(&bcast_output, session)?;
    }
    Ok(result)
}

pub(crate) fn derive_challenges_from_coinflip(
    x: &ResiduePoly<Z128>,
    g: usize,
    l: usize,
    roles: &[Role],
) -> HashMap<Role, Vec<ResiduePoly<Z128>>> {
    let mut hasher = Hasher::new();
    //Update hasher with x
    //Is this the correct way to do it in rust?
    for x_coef in x.coefs {
        hasher.update(&x_coef.0.to_le_bytes());
    }
    hasher.update(&g.to_le_bytes());

    roles
        .iter()
        .map(|role| {
            let mut hasher_cloned = hasher.clone();
            hasher_cloned.update(&role.0.to_le_bytes());
            let mut output_reader = hasher_cloned.finalize_xof();
            let mut challenges = vec![ResiduePoly::<Z128>::ZERO; l];
            for challenge in challenges.iter_mut() {
                let mut bytes_res_poly = [0u8; ResiduePoly::<Z128>::BIT_LENGTH >> 3];
                output_reader.fill(&mut bytes_res_poly);
                *challenge = ResiduePoly::<Z128>::from_bytes(&bytes_res_poly);
            }
            (*role, challenges)
        })
        .collect()
}

// Inputs:
// pads_shares maps a role to a vector of size m ( { r_g }_g in the protocol description)
// map_challenges maps a role to a vector of size l ( { x_{jg} }_j in the protocol description)
// secret_shares maps a role to a vector of size l ( { s_j }_j in the protocol description)
// Output:
// the share of the checking value for every role
pub(crate) fn compute_check_values(
    map_pads_shares: &HashMap<Role, Vec<ResiduePoly<Z128>>>,
    map_challenges: &HashMap<Role, Vec<ResiduePoly<Z128>>>,
    map_secret_shares: &HashMap<Role, Vec<ResiduePoly<Z128>>>,
    g: usize,
    my_role: Option<&Role>,
) -> anyhow::Result<BTreeMap<Role, ResiduePoly<Z128>>> {
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
                        .fold(ResiduePoly::<Z128>::ZERO, |acc, (x, s)| acc + x * s),
            ))
        })
        .try_collect()
}

//Verify that the sender for each lsl did give a 0 share to parties it is in dispute with
//and that the overall sharing is a degree t polynomial
pub(crate) fn verify_sender_challenge<R: RngCore, L: LargeSessionHandles<R>>(
    bcast_data: &HashMap<Role, MapsSharesChallenges>,
    session: &mut L,
    threshold: usize,
    result_map: &mut Option<HashMap<Role, Value>>,
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
                    != &ResiduePoly::<Z128>::ZERO
            {
                newly_corrupt.insert(*role_pi);
                tracing::warn!("Expected to find a 0 share for {pj_dispute_pi} from {role_pi} due to dispute. Adding it to corrupt");
                break;
            }
        }
        if !newly_corrupt.contains(role_pi) {
            //Check correct degree
            let indexed_shares = sharing_from_sender
                .iter()
                .map(|(role, share)| IndexedValue {
                    party_id: role.party_id(),
                    value: Value::Poly128(*share),
                })
                .collect_vec();
            let try_reconstruct = err_reconstruct(&indexed_shares, threshold, 0);

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

pub(crate) fn look_for_disputes<R: RngCore, L: LargeSessionHandles<R>>(
    bcast_data: &HashMap<Role, MapsSharesChallenges>,
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
mod tests {
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::Wrapping,
    };

    use itertools::Itertools;
    use rand::RngCore;
    use tokio::task::JoinSet;
    use tracing_test::traced_test;

    use crate::{
        computation::SessionId,
        execution::{
            broadcast::broadcast_with_corruption,
            coinflip::{Coinflip, RealCoinflip},
            distributed::DistributedTestRuntime,
            large_execution::share_dispute::{RealShareDispute, ShareDispute, ShareDisputeOutput},
            party::{Identity, Role},
            session::{BaseSessionHandles, LargeSessionHandles},
        },
        poly::Ring,
        residue_poly::ResiduePoly,
        shamir::ShamirGSharings,
        sharing::{constants::DISPUTE_STAT_SEC, vss::RealVss},
        value::BroadcastValue,
        Zero, Z128,
    };

    use super::{
        compute_check_values, derive_challenges_from_coinflip, look_for_disputes,
        send_receive_pads, verify_sender_challenge, verify_sharing, LocalSingleShare,
        MapsSharesChallenges, RealLocalSingleShare,
    };

    fn setup_parties_and_secrets(
        nb_parties: usize,
        nb_secrets: usize,
    ) -> (Vec<Identity>, HashMap<Role, Vec<ResiduePoly<Z128>>>) {
        let identities: Vec<Identity> = (0..nb_parties)
            .map(|party_nb| {
                let mut id_str = "localhost:500".to_owned();
                id_str.push_str(&party_nb.to_string());
                Identity(id_str)
            })
            .collect();

        let secrets: HashMap<Role, Vec<ResiduePoly<Z128>>> = (0..nb_parties)
            .map(|party_id| {
                let role_pi = Role::from_zero(party_id);
                (
                    role_pi,
                    (0..nb_secrets)
                        .map(|secret_idx| {
                            ResiduePoly::<Z128>::from_scalar(Wrapping(
                                ((party_id + 1) * nb_parties + secret_idx)
                                    .try_into()
                                    .unwrap(),
                            ))
                        })
                        .collect(),
                )
            })
            .collect();

        (identities, secrets)
    }

    type TrueCoinFlip = RealCoinflip<RealVss>;
    #[traced_test]
    #[test]
    fn test_lsl() {
        let nb_parties = 4;
        let nb_secrets = 10;
        let (identities, secrets) = setup_parties_and_secrets(nb_parties, nb_secrets);
        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            let s = secrets.get(&Role::from_zero(party_nb)).unwrap().clone();
            set.spawn(async move {
                (
                    party_nb,
                    RealLocalSingleShare::<TrueCoinFlip, RealShareDispute>::execute(
                        &mut session,
                        &s,
                    )
                    .await
                    .unwrap(),
                )
            });
        }

        let results = rt.block_on(async {
            let mut results = HashMap::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.insert(data.0, data.1);
            }
            results
        });

        assert_eq!(results.len(), nb_parties);

        //Check that all secrets reconstruct correctly
        for sender_id in 0..nb_parties {
            for secret_id in 0..nb_secrets {
                let mut vec_shares = vec![(0_usize, ResiduePoly::<Z128>::ZERO); nb_parties];
                for (share_idx, vec_share) in vec_shares.iter_mut().enumerate() {
                    *vec_share = (
                        share_idx + 1,
                        results
                            .get(&share_idx)
                            .unwrap()
                            .get(&Role::from_zero(sender_id))
                            .unwrap()[secret_id],
                    );
                }
                let shamir_sharing = ShamirGSharings { shares: vec_shares };
                let expected_result = secrets.get(&Role::from_zero(sender_id)).unwrap()[secret_id];
                assert_eq!(
                    expected_result,
                    shamir_sharing.reconstruct(threshold.into()).unwrap()
                );
            }
        }
    }

    //In this test party 2 lies about the shares it received from parties in lie_to
    async fn cheating_strategy_1<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
        lie_to: &[Role],
    ) -> anyhow::Result<HashMap<Role, Vec<ResiduePoly<Z128>>>> {
        //Keeps executing til verification passes
        loop {
            //ShareDispute will fill shares from corrupted players with 0s
            let mut shared_secrets = RealShareDispute::execute(session, secrets).await?;

            //Modify received shared frome parties in lie to
            for role in lie_to {
                let share_vec = shared_secrets.all_shares.get(role).unwrap();
                let mut new_shares = vec![ResiduePoly::<Z128>::ZERO; secrets.len()];
                for (idx, share) in share_vec.iter().enumerate() {
                    new_shares[idx] =
                        *share + ResiduePoly::from_scalar(Wrapping::<u128>(idx as u128 + 1));
                }
                shared_secrets.all_shares.insert(*role, new_shares);
            }

            let shared_pads = send_receive_pads::<R, L, RealShareDispute>(session).await?;

            let x = TrueCoinFlip::execute(session).await?;

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

    //In this test party 2 lies about the shares it received from party 3
    //We thus expected all the honest parties to add a dispute (P2,P3) and restart the protocol once.
    #[test]
    fn test_lsl_cheater_1() {
        let nb_parties = 4;
        let nb_secrets = 2;
        let (identities, secrets) = setup_parties_and_secrets(nb_parties, nb_secrets);
        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut malicious_set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            let s = secrets.get(&Role::from_zero(party_nb)).unwrap().clone();
            if party_nb == 1 {
                malicious_set.spawn(async move {
                    (
                        party_nb,
                        cheating_strategy_1(&mut session, &s, &[Role::from_zero(2)])
                            .await
                            .unwrap(),
                    )
                });
            } else {
                set.spawn(async move {
                    let res = (
                        party_nb,
                        RealLocalSingleShare::<TrueCoinFlip, RealShareDispute>::execute(
                            &mut session,
                            &s,
                        )
                        .await
                        .unwrap(),
                    );
                    assert!(session
                        .disputed_roles()
                        .get(&Role::from_zero(2))
                        .unwrap()
                        .contains(&Role::from_zero(1)));
                    res
                });
            }
        }

        let results = rt.block_on(async {
            let mut results = HashMap::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.insert(data.0, data.1);
            }
            while let Some(v) = malicious_set.join_next().await {
                let data = v.unwrap();
                results.insert(data.0, data.1);
            }
            results
        });

        assert_eq!(results.len(), nb_parties);

        //Check that all secrets reconstruct correctly
        for sender_id in 0..nb_parties {
            for secret_id in 0..nb_secrets {
                let mut vec_shares = Vec::<(usize, ResiduePoly<Z128>)>::new();
                for share_idx in 0..nb_parties {
                    vec_shares.push((
                        share_idx + 1,
                        results
                            .get(&share_idx)
                            .unwrap()
                            .get(&Role::from_zero(sender_id))
                            .unwrap()[secret_id],
                    ));
                }
                let shamir_sharing = ShamirGSharings { shares: vec_shares };
                let expected_result = secrets.get(&Role::from_zero(sender_id)).unwrap()[secret_id];
                //We expect to be able to reconstruct with at most 1 error comming from the malicious party
                assert_eq!(
                    expected_result,
                    shamir_sharing.err_reconstruct(threshold.into(), 1).unwrap()
                );
            }
        }
    }

    //In this test party 2 lies about the shares it received from party 3 and 4
    //We thus expected all the honest parties to see party 2 as corrupt due to too many disputes and restart the protocol once, ignoring it.
    #[test]
    fn test_lsl_cheater_2() {
        let nb_parties = 4;
        let nb_secrets = 2;
        let (identities, secrets) = setup_parties_and_secrets(nb_parties, nb_secrets);
        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut malicious_set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            let s = secrets.get(&Role::from_zero(party_nb)).unwrap().clone();
            if party_nb == 1 {
                malicious_set.spawn(async move {
                    (
                        party_nb,
                        cheating_strategy_1(
                            &mut session,
                            &s,
                            &[Role::from_zero(2), Role::from_zero(3)],
                        )
                        .await,
                    )
                });
            } else {
                set.spawn(async move {
                    let res = (
                        party_nb,
                        RealLocalSingleShare::<TrueCoinFlip, RealShareDispute>::execute(
                            &mut session,
                            &s,
                        )
                        .await
                        .unwrap(),
                    );
                    assert!(session.corrupt_roles().contains(&Role::from_zero(1)));
                    res
                });
            }
        }

        let results = rt.block_on(async {
            let mut results = HashMap::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.insert(data.0, data.1);
            }
            results
        });

        assert_eq!(results.len(), nb_parties - 1);

        //Check that all secrets reconstruct correctly
        for sender_id in 0..nb_parties {
            for secret_id in 0..nb_secrets {
                let mut vec_shares = Vec::<(usize, ResiduePoly<Z128>)>::new();
                for share_idx in 0..nb_parties {
                    if share_idx != 1 {
                        vec_shares.push((
                            share_idx + 1,
                            results
                                .get(&share_idx)
                                .unwrap()
                                .get(&Role::from_zero(sender_id))
                                .unwrap()[secret_id],
                        ));
                    }
                }
                let shamir_sharing = ShamirGSharings { shares: vec_shares };
                let expected_result = if sender_id == 1 {
                    ResiduePoly::<Z128>::ZERO
                } else {
                    secrets.get(&Role::from_zero(sender_id)).unwrap()[secret_id]
                };
                //We expect to be able to reconstruct with no error as we have identified the corrupt party
                //and thus we dont consider its shares
                assert_eq!(
                    expected_result,
                    shamir_sharing.err_reconstruct(threshold.into(), 0).unwrap()
                );
            }
        }
    }

    async fn malicious_verify_sharing<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &mut ShareDisputeOutput,
        pads: &ShareDisputeOutput,
        x: &ResiduePoly<Z128>,
        l: usize,
        ignore_list: &[Role],
    ) -> anyhow::Result<bool> {
        let (secrets_shares_all, my_shared_secrets) =
            (&mut secrets.all_shares, &mut secrets.shares_own_secret);
        let (pads_shares_all, my_shared_pads) = (&pads.all_shares, &pads.shares_own_secret);
        let m = (DISPUTE_STAT_SEC as f64 / ResiduePoly::<Z128>::BIT_LENGTH as f64).ceil() as usize;
        let roles = session.role_assignments().keys().cloned().collect_vec();
        let my_role = session.my_role()?;
        let mut result = true;
        for g in 0..m {
            let map_challenges = derive_challenges_from_coinflip(x, g, l, &roles);

            //Compute my share of check values for every local single share happening in parallel
            let map_share_check_values: BTreeMap<Role, ResiduePoly<Z128>> = compute_check_values(
                pads_shares_all,
                &map_challenges,
                secrets_shares_all,
                g,
                None,
            )?;

            //Compute the share of the check value for MY local single share
            let mut map_share_my_check_values: BTreeMap<Role, ResiduePoly<Z128>> =
                compute_check_values(
                    my_shared_pads,
                    &map_challenges,
                    my_shared_secrets,
                    g,
                    Some(&my_role.clone()),
                )?;

            for role in ignore_list {
                map_share_my_check_values.remove(role);
            }

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
            let mut bcast_output = HashMap::<Role, MapsSharesChallenges>::new();
            let mut bcast_corrupts = HashSet::<Role>::new();
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
                secrets_shares_all.insert(role_pi, vec![ResiduePoly::<Z128>::ZERO; l]);
                session.add_corrupt(role_pi)?;
            }

            result &= look_for_disputes(&bcast_output, session)?;
        }
        Ok(result)
    }
    //In this test party 2 doesnt broadcast all a full set of values as sender.
    //In particular, it ignores parties in the ignore list
    async fn cheating_strategy_2<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
        ignore_list: &[Role],
    ) -> anyhow::Result<HashMap<Role, Vec<ResiduePoly<Z128>>>> {
        //Keeps executing til verification passes
        loop {
            //ShareDispute will fill shares from corrupted players with 0s
            let mut shared_secrets = RealShareDispute::execute(session, secrets).await?;

            let shared_pads = send_receive_pads::<R, L, RealShareDispute>(session).await?;

            let x = TrueCoinFlip::execute(session).await?;

            if malicious_verify_sharing(
                session,
                &mut shared_secrets,
                &shared_pads,
                &x,
                secrets.len(),
                ignore_list,
            )
            .await?
            {
                return Ok(shared_secrets.all_shares);
            }
        }
    }

    //In this test party 2 'ignores' party 3 in its broadcasts
    //We thus expected all the honest parties to see party 2 as corrupt and output default 0 shares for when its a sender.
    #[test]
    fn test_lsl_cheater_3() {
        let nb_parties = 4;
        let nb_secrets = 2;
        let (identities, secrets) = setup_parties_and_secrets(nb_parties, nb_secrets);
        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut malicious_set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            let s = secrets.get(&Role::from_zero(party_nb)).unwrap().clone();
            if party_nb == 1 {
                malicious_set.spawn(async move {
                    (
                        party_nb,
                        cheating_strategy_2(&mut session, &s, &[Role::from_zero(2)]).await,
                    )
                });
            } else {
                set.spawn(async move {
                    let res = (
                        party_nb,
                        RealLocalSingleShare::<TrueCoinFlip, RealShareDispute>::execute(
                            &mut session,
                            &s,
                        )
                        .await
                        .unwrap(),
                    );
                    assert!(session.corrupt_roles().contains(&Role::from_zero(1)));
                    res
                });
            }
        }

        let results = rt.block_on(async {
            let mut results = HashMap::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.insert(data.0, data.1);
            }
            results
        });

        assert_eq!(results.len(), nb_parties - 1);

        //Check that all secrets reconstruct correctly
        for sender_id in 0..nb_parties {
            for secret_id in 0..nb_secrets {
                let mut vec_shares = Vec::<(usize, ResiduePoly<Z128>)>::new();
                for share_idx in 0..nb_parties {
                    if share_idx != 1 {
                        vec_shares.push((
                            share_idx + 1,
                            results
                                .get(&share_idx)
                                .unwrap()
                                .get(&Role::from_zero(sender_id))
                                .unwrap()[secret_id],
                        ));
                    }
                }
                let shamir_sharing = ShamirGSharings { shares: vec_shares };
                let expected_result = if sender_id == 1 {
                    ResiduePoly::<Z128>::ZERO
                } else {
                    secrets.get(&Role::from_zero(sender_id)).unwrap()[secret_id]
                };
                //We expect to be able to reconstruct with no error as we have identified the corrupt party
                //and thus we dont consider its shares
                assert_eq!(
                    expected_result,
                    shamir_sharing.err_reconstruct(threshold.into(), 0).unwrap()
                );
            }
        }
    }
}
