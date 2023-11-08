use std::collections::{BTreeMap, HashMap, HashSet};

use async_trait::async_trait;
use itertools::Itertools;
use rand::RngCore;

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        broadcast::broadcast_with_corruption,
        coinflip::Coinflip,
        large_execution::share_dispute::{ShareDispute, ShareDisputeOutputDouble},
        party::Role,
        session::LargeSessionHandles,
    },
    poly::Ring,
    residue_poly::ResiduePoly,
    value::{BroadcastValue, Value},
    Sample, Zero, Z128,
};

use super::{
    constants::DISPUTE_STAT_SEC,
    local_single_share::{
        compute_check_values, derive_challenges_from_coinflip, look_for_disputes,
        verify_sender_challenge, MapsSharesChallenges,
    },
};

//TODO: Here until we actually use it
#[allow(dead_code)]
pub struct DoubleShares {
    pub(crate) share_t: Vec<ResiduePoly<Z128>>,
    pub(crate) share_2t: Vec<ResiduePoly<Z128>>,
}

#[async_trait]
pub trait LocalDoubleShare: Send + Default {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<HashMap<Role, DoubleShares>>;
}

pub(crate) type MapsDoubleSharesChallenges = (
    BTreeMap<Role, ResiduePoly<Z128>>,
    BTreeMap<Role, ResiduePoly<Z128>>,
    BTreeMap<Role, ResiduePoly<Z128>>,
    BTreeMap<Role, ResiduePoly<Z128>>,
);

#[derive(Default)]
pub struct RealLocalDoubleShare<C: Coinflip, S: ShareDispute> {
    _marker_coinflip: std::marker::PhantomData<C>,
    _marker_share_dispute: std::marker::PhantomData<S>,
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute> LocalDoubleShare for RealLocalDoubleShare<C, S> {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<HashMap<Role, DoubleShares>> {
        //Keeps executing til verification passes
        loop {
            //ShareDispute will fill shares from corrupted players with 0s
            let mut shared_secrets_double = S::execute_double(session, secrets).await?;

            let shared_pads_double = send_receive_pads_double::<R, L, S>(session).await?;

            let x = C::execute(session).await?;

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
    }
}

//Format the double sharing correctly for output
fn format_output(
    shared_secrets_double: ShareDisputeOutputDouble,
) -> anyhow::Result<HashMap<Role, DoubleShares>> {
    let (output_t, mut output_2t) = (
        shared_secrets_double.output_t.all_shares,
        shared_secrets_double.output_2t.all_shares,
    );
    let result: HashMap<Role, DoubleShares> = output_t
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

async fn send_receive_pads_double<R, L, S>(
    session: &mut L,
) -> anyhow::Result<ShareDisputeOutputDouble>
where
    R: RngCore,
    L: LargeSessionHandles<R>,
    S: ShareDispute,
{
    let m = (DISPUTE_STAT_SEC as f64 / ResiduePoly::<Z128>::BIT_LENGTH as f64).ceil() as usize;
    let my_pads: Vec<ResiduePoly<Z128>> = (0..m)
        .map(|_| ResiduePoly::<Z128>::sample(session.rng()))
        .collect();
    S::execute_double(session, &my_pads).await
}

async fn verify_sharing<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    secrets_double: &mut ShareDisputeOutputDouble,
    pads_double: &ShareDisputeOutputDouble,
    x: &ResiduePoly<Z128>,
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
    let m = (DISPUTE_STAT_SEC as f64 / ResiduePoly::<Z128>::BIT_LENGTH as f64).ceil() as usize;
    let my_role = session.my_role()?;
    let mut result = true;

    for g in 0..m {
        let map_challenges = derive_challenges_from_coinflip(x, g, l, &roles);

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
        let bcast_data = broadcast_with_corruption(
            session,
            crate::value::BroadcastValue::LocalDoubleShare((
                map_share_check_values_t,
                map_share_check_values_2t,
                map_share_my_check_values_t,
                map_share_my_check_values_2t,
            )),
        )
        .await?;

        //Split Broadcast data into degree t and 2t, allowing to mimic behaviour of local single sharing
        let mut bcast_data_t = HashMap::<Role, MapsSharesChallenges>::new();
        let mut bcast_data_2t = HashMap::<Role, MapsSharesChallenges>::new();
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
            Some(HashMap::<Role, Value>::new()),
            Some(HashMap::<Role, Value>::new()),
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

        let result_map_t = result_map_t.ok_or_else(|| {
            anyhow_error_and_log("Can not unwrap result_map_t I created.".to_string())
        })?;
        let result_map_2t = result_map_2t.ok_or_else(|| {
            anyhow_error_and_log("Can not unwrap result_map_2t I created.".to_string())
        })?;

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
            secrets_shares_all_t.insert(role_pi, vec![ResiduePoly::<Z128>::ZERO; l]);
            secrets_shares_all_2t.insert(role_pi, vec![ResiduePoly::<Z128>::ZERO; l]);
            session.add_corrupt(role_pi)?;
        }
        result &= look_for_disputes(&bcast_data_t, session)?;
        result &= look_for_disputes(&bcast_data_2t, session)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, num::Wrapping};

    use rand::RngCore;
    use tokio::task::JoinSet;

    use crate::{
        computation::SessionId,
        execution::{
            coinflip::{Coinflip, RealCoinflip},
            distributed::DistributedTestRuntime,
            large_execution::share_dispute::{RealShareDispute, ShareDispute},
            party::{Identity, Role},
            session::{BaseSessionHandles, LargeSessionHandles},
        },
        residue_poly::ResiduePoly,
        shamir::ShamirGSharings,
        sharing::{
            local_double_share::{LocalDoubleShare, RealLocalDoubleShare},
            vss::RealVss,
        },
        Zero, Z128,
    };

    use super::{format_output, send_receive_pads_double, verify_sharing, DoubleShares};

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
                let role_pi = Role::indexed_by_zero(party_id);
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
    #[test]
    fn test_ldl() {
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
            let s = secrets
                .get(&Role::indexed_by_zero(party_nb))
                .unwrap()
                .clone();
            set.spawn(async move {
                (
                    party_nb,
                    RealLocalDoubleShare::<TrueCoinFlip, RealShareDispute>::execute(
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
                let mut vec_shares_t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); nb_parties];
                let mut vec_shares_2t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); nb_parties];
                for (share_idx, (vec_share_t, vec_share_2t)) in vec_shares_t
                    .iter_mut()
                    .zip(vec_shares_2t.iter_mut())
                    .enumerate()
                {
                    *vec_share_t = (
                        share_idx + 1,
                        results
                            .get(&share_idx)
                            .unwrap()
                            .get(&Role::indexed_by_zero(sender_id))
                            .unwrap()
                            .share_t[secret_id],
                    );
                    *vec_share_2t = (
                        share_idx + 1,
                        results
                            .get(&share_idx)
                            .unwrap()
                            .get(&Role::indexed_by_zero(sender_id))
                            .unwrap()
                            .share_2t[secret_id],
                    );
                }
                let shamir_sharing_t = ShamirGSharings {
                    shares: vec_shares_t,
                };
                let shamir_sharing_2t = ShamirGSharings {
                    shares: vec_shares_2t,
                };
                let expected_result =
                    secrets.get(&Role::indexed_by_zero(sender_id)).unwrap()[secret_id];
                assert_eq!(
                    expected_result,
                    shamir_sharing_t.reconstruct(threshold.into()).unwrap()
                );

                assert_eq!(
                    expected_result,
                    shamir_sharing_2t
                        .reconstruct(2 * threshold as usize)
                        .unwrap()
                );
            }
        }
    }

    //In this test party 2 lies about the degree t shares it received from parties in lie_to
    async fn cheating_strategy_1<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
        lie_to: &[Role],
    ) -> anyhow::Result<HashMap<Role, DoubleShares>> {
        //Keeps executing til verification passes
        loop {
            //ShareDispute will fill shares from corrupted players with 0s
            let mut shared_secrets_double =
                RealShareDispute::execute_double(session, secrets).await?;

            //Modify received shared frome parties in lie to
            for role in lie_to {
                let share_vec = shared_secrets_double.output_t.all_shares.get(role).unwrap();
                let mut new_shares = vec![ResiduePoly::<Z128>::ZERO; secrets.len()];
                for (idx, share) in share_vec.iter().enumerate() {
                    new_shares[idx] =
                        *share + ResiduePoly::from_scalar(Wrapping::<u128>(idx as u128 + 1));
                }
                shared_secrets_double
                    .output_t
                    .all_shares
                    .insert(*role, new_shares);
            }

            let shared_pads = send_receive_pads_double::<R, L, RealShareDispute>(session).await?;

            let x = TrueCoinFlip::execute(session).await?;

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
    }

    //In this test party 2 lies about the shares it received from party 3
    //We thus expected all the honest parties to add a dispute (P2,P3) and restart the protocol once.
    #[test]
    fn test_ldl_cheater_1() {
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
            let s = secrets
                .get(&Role::indexed_by_zero(party_nb))
                .unwrap()
                .clone();
            if party_nb == 1 {
                malicious_set.spawn(async move {
                    (
                        party_nb,
                        cheating_strategy_1(&mut session, &s, &[Role::indexed_by_zero(2)])
                            .await
                            .unwrap(),
                    )
                });
            } else {
                set.spawn(async move {
                    let res = (
                        party_nb,
                        RealLocalDoubleShare::<TrueCoinFlip, RealShareDispute>::execute(
                            &mut session,
                            &s,
                        )
                        .await
                        .unwrap(),
                    );
                    assert!(session
                        .disputed_roles()
                        .get(&Role::indexed_by_zero(2))
                        .unwrap()
                        .contains(&Role::indexed_by_zero(1)));
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
                let mut vec_shares_t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); nb_parties];
                let mut vec_shares_2t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); nb_parties];
                for (share_idx, (vec_share_t, vec_share_2t)) in vec_shares_t
                    .iter_mut()
                    .zip(vec_shares_2t.iter_mut())
                    .enumerate()
                {
                    //On sharing from P3, dont consider P2s contribution but instead default 0 due to dispute
                    //Note that we also have the default values for share of P2 to P3, but this one is correctly
                    //output by the protocol because P3 doesnt lie on its received shares
                    if (sender_id == 2) && (share_idx == 1) {
                        *vec_share_t = (share_idx + 1, ResiduePoly::<Z128>::ZERO);
                        *vec_share_2t = (share_idx + 1, ResiduePoly::<Z128>::ZERO);
                    } else {
                        *vec_share_t = (
                            share_idx + 1,
                            results
                                .get(&share_idx)
                                .unwrap()
                                .get(&Role::indexed_by_zero(sender_id))
                                .unwrap()
                                .share_t[secret_id],
                        );
                        *vec_share_2t = (
                            share_idx + 1,
                            results
                                .get(&share_idx)
                                .unwrap()
                                .get(&Role::indexed_by_zero(sender_id))
                                .unwrap()
                                .share_2t[secret_id],
                        );
                    }
                }
                let shamir_sharing_t = ShamirGSharings {
                    shares: vec_shares_t,
                };
                let shamir_sharing_2t = ShamirGSharings {
                    shares: vec_shares_2t,
                };
                let expected_result =
                    secrets.get(&Role::indexed_by_zero(sender_id)).unwrap()[secret_id];
                assert_eq!(
                    expected_result,
                    shamir_sharing_t
                        .err_reconstruct(threshold.into(), 0)
                        .unwrap()
                );

                assert_eq!(
                    expected_result,
                    shamir_sharing_2t
                        .err_reconstruct(2 * threshold as usize, 0)
                        .unwrap()
                );
            }
        }
    }

    #[test]
    fn test_ldl_cheater_2() {
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
            let s = secrets
                .get(&Role::indexed_by_zero(party_nb))
                .unwrap()
                .clone();
            if party_nb == 1 {
                malicious_set.spawn(async move {
                    (
                        party_nb,
                        cheating_strategy_1(
                            &mut session,
                            &s,
                            &[Role::indexed_by_zero(2), Role::indexed_by_zero(3)],
                        )
                        .await,
                    )
                });
            } else {
                set.spawn(async move {
                    let res = (
                        party_nb,
                        RealLocalDoubleShare::<TrueCoinFlip, RealShareDispute>::execute(
                            &mut session,
                            &s,
                        )
                        .await
                        .unwrap(),
                    );
                    assert!(session.corrupt_roles().contains(&Role::indexed_by_zero(1)));
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
                let mut vec_shares_t = Vec::<(usize, ResiduePoly<Z128>)>::new(); //vec![(0_usize, ResiduePoly::<Z128>::ZERO); nb_parties];
                let mut vec_shares_2t = Vec::<(usize, ResiduePoly<Z128>)>::new(); // vec![(0_usize, ResiduePoly::<Z128>::ZERO); nb_parties];
                for share_idx in 0..nb_parties {
                    if share_idx != 1 {
                        vec_shares_t.push((
                            share_idx + 1,
                            results
                                .get(&share_idx)
                                .unwrap()
                                .get(&Role::indexed_by_zero(sender_id))
                                .unwrap()
                                .share_t[secret_id],
                        ));
                        vec_shares_2t.push((
                            share_idx + 1,
                            results
                                .get(&share_idx)
                                .unwrap()
                                .get(&Role::indexed_by_zero(sender_id))
                                .unwrap()
                                .share_2t[secret_id],
                        ));
                    }
                }
                let shamir_sharing_t = ShamirGSharings {
                    shares: vec_shares_t,
                };
                let shamir_sharing_2t = ShamirGSharings {
                    shares: vec_shares_2t,
                };
                let expected_result = if sender_id == 1 {
                    ResiduePoly::<Z128>::ZERO
                } else {
                    secrets.get(&Role::indexed_by_zero(sender_id)).unwrap()[secret_id]
                };

                assert_eq!(
                    expected_result,
                    shamir_sharing_t
                        .err_reconstruct(threshold.into(), 0)
                        .unwrap()
                );

                assert_eq!(
                    expected_result,
                    shamir_sharing_2t
                        .err_reconstruct(2 * threshold as usize, 0)
                        .unwrap()
                );
            }
        }
    }
}
