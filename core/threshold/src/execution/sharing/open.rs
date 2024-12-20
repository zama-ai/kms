use itertools::Itertools;
use rand::{CryptoRng, Rng};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{collections::HashMap, sync::Arc};
use tokio::{task::JoinSet, time::error::Elapsed};
use tracing::instrument;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::{generic_receive_from_all, send_to_all},
        online::preprocessing::constants::BATCH_SIZE_BITS,
        runtime::{party::Role, session::BaseSessionHandles},
    },
    networking::value::NetworkValue,
};

use super::{
    shamir::{
        fill_indexed_shares, reconstruct_w_errors_async, reconstruct_w_errors_sync, ShamirSharings,
    },
    share::Share,
};

type JobResultType<Z> = (Role, anyhow::Result<Vec<Z>>);
type ReconsFunc<Z> = fn(
    num_parties: usize,
    degree: usize,
    threshold: usize,
    num_bots: usize,
    sharing: &ShamirSharings<Z>,
) -> anyhow::Result<Option<Z>>;
/// Helper function of robust reconstructions which collect the shares and tries to reconstruct
///
/// Takes as input:
///
/// - the session_parameters
/// - indexed_share as the indexed share of the local party
/// - degree as the degree of the secret sharing
/// - max_num_errors as the max. number of errors we allow (this is session.threshold)
/// - a set of jobs to receive the shares from the other parties
async fn try_reconstruct_from_shares<
    Z: Ring + ErrorCorrect,
    R: Rng + CryptoRng,
    B: BaseSessionHandles<R>,
>(
    session: &B,
    sharings: &mut [ShamirSharings<Z>],
    degree: usize,
    jobs: &mut JoinSet<Result<JobResultType<Z>, Elapsed>>,
    reconstruct_fn: ReconsFunc<Z>,
) -> anyhow::Result<Option<Vec<Z>>> {
    let num_parties = session.num_parties();
    let threshold = session.threshold();
    let mut num_bots = session.corrupt_roles().len();
    let num_secrets = sharings.len();

    //Start awaiting on receive jobs to retrieve the shares
    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        match joined_result {
            Ok((party_id, data)) => {
                if let Ok(values) = data {
                    fill_indexed_shares(sharings, values, num_secrets, party_id)?;
                } else if let Err(e) = data {
                    tracing::warn!(
                        "(Share reconstruction) Received malformed data from {party_id}:  {:?}",
                        e
                    );
                    num_bots += 1;
                }
            }
            Err(e) => {
                // TODO can we see the party_id that correspond to the job?
                tracing::warn!("(Share reconstruction) Some party has timed out:  {:?}", e);
                num_bots += 1;
            }
        }
        //Note: here we keep waiting on new shares until we have all of the values opened.
        let res: Option<Vec<_>> = sharings
            .par_iter()
            // Here we want to use par_iter for opening the huge batches
            // present in DKG, but we want to avoid using it for
            // DKG preproc where we have lots of sessions in parallel
            // dealing with small batches.
            // Because for the case with lots of sessions and small batches,
            // we don't want say P1 to highly parallelize session 1 first
            // and P2 highly parallelize session 2 first.
            // For DKG preproc, the prallelization happens through spawning lots of sessions,
            // which are more likely to distribute workload similarly across the parties
            // as network call acts as a sync points across parties
            .with_min_len(BATCH_SIZE_BITS)
            .map(|sharing| {
                reconstruct_fn(num_parties, degree, threshold as usize, num_bots, sharing)
                    .unwrap_or_default()
            })
            .collect();

        //Only prematurely shutdown the jobs if we have managed to reconstruct everything
        if res.is_some() {
            jobs.shutdown().await;
            return Ok(res);
        }
    }

    //If we've reached this point without being able to reconstruct, we fail
    Err(anyhow_error_and_log(
        "Could not reconstruct the sharing".to_string(),
    ))
}

pub async fn robust_open_to_all<
    Z: Ring + ErrorCorrect,
    R: Rng + CryptoRng,
    B: BaseSessionHandles<R>,
>(
    session: &B,
    share: Z,
    degree: usize,
) -> anyhow::Result<Option<Z>> {
    let res = robust_opens_to_all(session, &[share], degree).await?;
    match res {
        Some(mut r) => Ok(r.pop()),
        _ => Ok(None),
    }
}

/// Try to reconstruct to all the secret which corresponds to the provided share.
/// Considering I as a player already hold my own share of the secret
///
/// Inputs:
/// - session
/// - shares of the secrets to open
/// - degree of the sharing
///
/// Output:
/// - The reconstructed secrets if reconstruction for all was possible
#[instrument(name="RobustOpen",skip(session,shares),fields(session_id= ?session.session_id(), own_identity = ?session.own_identity(),batch_size = ?shares.len()))]
pub async fn robust_opens_to_all<
    Z: Ring + ErrorCorrect,
    R: Rng + CryptoRng,
    B: BaseSessionHandles<R>,
>(
    session: &B,
    shares: &[Z],
    degree: usize,
) -> anyhow::Result<Option<Vec<Z>>> {
    //Might need to chunk the opening into multiple ones due to network limits
    let chunk_size = super::constants::MAX_MESSAGE_BYTE_SIZE / (Z::BIT_LENGTH >> 3);

    let mut result = Vec::new();
    for shares in shares.chunks(chunk_size) {
        let own_role = session.my_role()?;

        send_to_all(
            session,
            &own_role,
            NetworkValue::VecRingValue(shares.to_vec()),
        )
        .await?;

        let mut jobs = JoinSet::<Result<(Role, anyhow::Result<Vec<Z>>), Elapsed>>::new();
        //Note: we give the set of corrupt parties as the non_answering_parties argument
        //Thus generic_receive_from_all will not receive from corrupt parties.
        generic_receive_from_all(
            &mut jobs,
            session,
            &own_role,
            Some(session.corrupt_roles()),
            |msg, _id| match msg {
                NetworkValue::VecRingValue(v) => Ok(v),
                _ => Err(anyhow_error_and_log(
                    "Received something else than a Ring value in robust open to all".to_string(),
                )),
            },
        )?;

        //Start filling sharings with my own shares
        let mut sharings = shares
            .iter()
            .map(|share| ShamirSharings::create(vec![Share::new(own_role, *share)]))
            .collect_vec();

        let reconstruct_fn = match session.network().get_network_mode() {
            crate::networking::NetworkMode::Sync => reconstruct_w_errors_sync,
            crate::networking::NetworkMode::Async => reconstruct_w_errors_async,
        };

        match try_reconstruct_from_shares(session, &mut sharings, degree, &mut jobs, reconstruct_fn)
            .await?
        {
            Some(res) => result.extend(res),
            None => return Ok(None),
        }
    }
    Ok(Some(result))
}

/// Try to reconstruct a secret to a specific party.
pub async fn robust_open_to<
    Z: Ring + ErrorCorrect,
    R: Rng + CryptoRng,
    B: BaseSessionHandles<R>,
>(
    session: &B,
    share: Z,
    degree: usize,
    output_party: &Role,
) -> anyhow::Result<Option<Z>> {
    let res = robust_opens_to(session, &[share], degree, output_party).await?;
    match res {
        Some(mut r) => Ok(r.pop()),
        _ => Ok(None),
    }
}

/// Try to reconstruct secrets to a specific party.
pub async fn robust_opens_to<
    Z: Ring + ErrorCorrect,
    R: Rng + CryptoRng,
    B: BaseSessionHandles<R>,
>(
    session: &B,
    shares: &[Z],
    degree: usize,
    output_party: &Role,
) -> anyhow::Result<Option<Vec<Z>>> {
    let shares = HashMap::from([(*output_party, shares.to_vec())]);
    multi_robust_opens_to(session, &shares, degree).await
}

/// Try to reconstruct different secrets to different specific parties.
#[instrument(name="RobustOpenTo",skip(session,shares),fields(session_id= ?session.session_id(), own_identity = ?session.own_identity(),num_receivers = ?shares.len()))]
pub async fn multi_robust_opens_to<
    Z: Ring + ErrorCorrect,
    R: Rng + CryptoRng,
    B: BaseSessionHandles<R>,
>(
    session: &B,
    shares: &HashMap<Role, Vec<Z>>,
    degree: usize,
) -> anyhow::Result<Option<Vec<Z>>> {
    let my_role = session.my_role()?;
    session.network().increase_round_counter()?;
    //First send all we have to send
    for (receiver_role, values) in shares {
        if receiver_role == &my_role {
            continue;
        } else {
            let receiver = session.identity_from(receiver_role)?;

            let networking = Arc::clone(session.network());

            networking
                .send(
                    NetworkValue::VecRingValue(values.to_vec()).to_network(),
                    &receiver,
                )
                .await?;
        }
    }
    //Then listen if need be
    let result = if let Some(values) = shares.get(&my_role) {
        let mut set = JoinSet::new();

        //Note: we give the set of corrupt parties as the non_answering_parties argument
        //Thus generic_receive_from_all will not receive from corrupt parties.
        generic_receive_from_all(
            &mut set,
            session,
            &my_role,
            Some(session.corrupt_roles()),
            |msg, _id| match msg {
                NetworkValue::VecRingValue(v) => Ok(v),
                _ => Err(anyhow_error_and_log(
                    "Received something else than a Ring value in robust open to all".to_string(),
                )),
            },
        )?;
        let mut sharings = values
            .iter()
            .map(|share| ShamirSharings::create(vec![Share::new(my_role, *share)]))
            .collect_vec();

        let reconstruct_fn = match session.network().get_network_mode() {
            crate::networking::NetworkMode::Sync => reconstruct_w_errors_sync,
            crate::networking::NetworkMode::Async => reconstruct_w_errors_async,
        };
        try_reconstruct_from_shares(session, &mut sharings, degree, &mut set, reconstruct_fn)
            .await?
    } else {
        None
    };
    Ok(result)
}

#[cfg(test)]
mod test {
    use std::num::Wrapping;

    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::SeedableRng;

    use crate::execution::sharing::shamir::InputOp;
    use crate::networking::NetworkMode;
    use crate::{
        algebra::{
            galois_rings::degree_8::ResiduePolyF8, galois_rings::degree_8::ResiduePolyF8Z128,
        },
        execution::{
            runtime::session::{LargeSession, ParameterHandles},
            sharing::{open::robust_opens_to_all, shamir::ShamirSharings},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    async fn open_task(session: LargeSession) -> Vec<ResiduePolyF8Z128> {
        let parties = 4;
        let threshold = 1;
        let num_secrets = 10;
        let mut rng = AesRng::seed_from_u64(0);
        let shares = (0..num_secrets)
            .map(|idx| {
                ShamirSharings::share(
                    &mut rng,
                    ResiduePolyF8::from_scalar(Wrapping(idx)),
                    parties,
                    threshold,
                )
                .unwrap()
                .shares
                .get(session.my_role().unwrap().zero_based())
                .unwrap()
                .value()
            })
            .collect_vec();
        let res = robust_opens_to_all(&session, &shares, threshold)
            .await
            .unwrap()
            .unwrap();
        for (idx, r) in res.clone().into_iter().enumerate() {
            assert_eq!(r.to_scalar().unwrap(), Wrapping::<u128>(idx as u128));
        }
        res
    }

    #[test]
    fn test_robust_open_all_sync() {
        let parties = 4;
        let threshold = 1;
        // expect a single round for opening

        let _ = execute_protocol_large::<ResiduePolyF8Z128, _, _>(
            parties,
            threshold,
            Some(1),
            NetworkMode::Sync,
            None,
            &mut open_task,
        );
    }

    #[test]
    fn test_robust_open_all_async() {
        let parties = 4;
        let threshold = 1;
        // expect a single round for opening

        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let _ = execute_protocol_large::<ResiduePolyF8Z128, _, _>(
            parties,
            threshold,
            Some(1),
            NetworkMode::Async,
            Some(delay_vec),
            &mut open_task,
        );
    }
}
