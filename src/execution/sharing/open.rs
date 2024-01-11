use std::{collections::HashSet, sync::Arc};

use itertools::Itertools;
use rand::RngCore;
use tokio::{task::JoinSet, time::error::Elapsed};

use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::{anyhow_error_and_log, anyhow_error_and_warn_log},
    execution::{
        communication::broadcast::{generic_receive_from_all, send_to_all},
        runtime::{
            party::Role,
            session::{BaseSessionHandles, ParameterHandles},
        },
    },
    networking::value::NetworkValue,
};

use super::{
    shamir::{ShamirRing, ShamirSharing},
    share::Share,
};

fn fill_indexed_shares<Z: Ring>(
    sharings: &mut [ShamirSharing<Z>],
    values: Vec<Z>,
    num_values: usize,
    party_id: Role,
) -> anyhow::Result<()> {
    let values_len = values.len();
    values
        .into_iter()
        .zip(sharings.iter_mut())
        .try_for_each(|(v, sharing)| sharing.add_share(Share::new(party_id, v)))?;

    if values_len < num_values {
        for sharing in sharings.iter_mut().skip(values_len) {
            sharing.add_share(Share::new(party_id, Z::ZERO))?;
        }
    }
    Ok(())
}

type JobResultType<Z> = (Role, anyhow::Result<Vec<Z>>);
/// Helper function of robust reconstructions which collect the shares and tries to reconstruct
/// Takes as input:
/// - the session_parameters
/// - indexed_share as the indexed share of the local party
/// - degree as the degree of the secret sharing
/// - t as the max. number of errors we allow (if no party has been flagged as corrupt, this is session.threshold)
/// - a set of jobs to receive the shares from the other parties
async fn try_reconstruct_from_shares<Z: ShamirRing, P: ParameterHandles>(
    session_parameters: &P,
    sharings: &mut [ShamirSharing<Z>],
    degree: usize,
    threshold: usize,
    jobs: &mut JoinSet<Result<JobResultType<Z>, Elapsed>>,
) -> anyhow::Result<Option<Vec<Z>>> {
    let num_parties = session_parameters.amount_of_parties();
    let own_role = session_parameters.my_role()?;
    let num_secrets = sharings.len();
    let mut answering_parties = HashSet::<Role>::new();

    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        if let Ok((party_id, data)) = joined_result {
            answering_parties.insert(party_id);
            if let Ok(values) = data {
                fill_indexed_shares(sharings, values, num_secrets, party_id)?;
            } else if let Err(e) = data {
                tracing::warn!(
                    "(Share reconstruction) Received malformed data from {party_id}:  {:?}",
                    e
                );
                fill_indexed_shares(sharings, [].to_vec(), num_secrets, party_id)?;
            }
        }

        //Note: here we keep waiting on new shares until we have all of the values opened.
        //Also, not sure we want to try reconstruct stuff before having heard from all parties
        //at least in the sync case, waiting for d+2t+1, basically means waiting for everyone.
        //reconstruct_w_errors_sync will just instantly return None for all
        let res: Option<Vec<_>> = sharings
            .iter()
            .map(|sharing| {
                if let Ok(Some(r)) =
                    reconstruct_w_errors_sync(num_parties, degree, threshold, sharing)
                {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        if let Some(r) = res {
            jobs.shutdown().await;
            return Ok(Some(r));
        }
    }

    //If we haven't yet been able to reconstruct it may be because we haven't heard from all parties
    //In which case we have to know if we knew those were already malicious.
    //If not, we have to try reconstruct with those parties considered as malicious (i.e. w/ updated threshold)
    let num_known_corrupt = session_parameters.threshold() as usize - threshold;
    let mut num_non_answering = 0;
    for role in session_parameters.role_assignments().keys() {
        if !answering_parties.contains(role) && role != &own_role {
            tracing::warn!("(Share reconstruction) Party {role} timed out.");
            num_non_answering += 1;
        }
    }
    //If we have more non-answering parties than expected by previous malicious set
    //try to reconstruct with updated threshold
    //If there is even one that can not be opened at this point,
    //then we will error out
    if num_non_answering > num_known_corrupt {
        let updated_threshold = session_parameters.threshold() as usize - num_non_answering;
        let res: Option<Vec<_>> = sharings
            .iter()
            .map(|sharing| {
                if let Ok(Some(r)) =
                    reconstruct_w_errors_sync(num_parties, degree, updated_threshold, sharing)
                {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        if let Some(r) = res {
            return Ok(Some(r));
        }
    }
    Err(anyhow_error_and_log(
        "Could not reconstruct the sharing".to_string(),
    ))
}

/// Core algorithm for robust reconstructions which tries to reconstruct from a collection of shares
/// Takes as input:
/// - num_parties as number of parties
/// - degree as the degree of the sharing (usually either t or 2t)
/// - threshold as the threshold of maximum corruptions
/// - indexed_shares as the indexed shares of the parties
/// NOTE: When needed, inplement the async version
pub fn reconstruct_w_errors_sync<Z: ShamirRing>(
    num_parties: usize,
    degree: usize,
    threshold: usize,
    sharing: &ShamirSharing<Z>,
) -> anyhow::Result<Option<Z>> {
    if degree + 2 * threshold < num_parties && sharing.shares.len() > degree + 2 * threshold {
        let opened = sharing.err_reconstruct(degree, threshold)?;
        tracing::debug!(
            "managed to reconstruct with given {:?} shares",
            sharing.shares.len()
        );
        return Ok(Some(opened));
    } else if degree + 2 * threshold >= num_parties {
        return Err(anyhow_error_and_warn_log(format!("Can NOT reconstruct with degree {degree}, threshold {threshold} and num_parties {num_parties}")));
    }

    Ok(None)
}

pub async fn robust_open_to_all<Z: ShamirRing, R: RngCore, B: BaseSessionHandles<R>>(
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
///
/// Inputs:
/// - session
/// - shares of the secrets to open
/// - degree of the sharing
///
/// Output:
/// - The reconstructed secrets if reconstruction for all was possible
pub async fn robust_opens_to_all<Z: ShamirRing, R: RngCore, B: BaseSessionHandles<R>>(
    session: &B,
    shares: &[Z],
    degree: usize,
) -> anyhow::Result<Option<Vec<Z>>> {
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

    let mut sharings = shares
        .iter()
        .map(|share| ShamirSharing::create(vec![Share::new(own_role, *share)]))
        .collect_vec();
    //Note: We are not even considering shares for the already known corrupt parties,
    //thus the effective threshold at this point is the "real" threshold - the number of known corrupt parties
    let threshold = session.threshold() as usize - session.corrupt_roles().len();
    try_reconstruct_from_shares(session, &mut sharings, degree, threshold, &mut jobs).await
}

pub async fn robust_open_to<Z: ShamirRing, R: RngCore + Send, B: BaseSessionHandles<R>>(
    session: &B,
    share: Z,
    degree: usize,
    role: &Role,
    output_party_id: usize,
) -> anyhow::Result<Option<Z>> {
    let res = robust_opens_to(session, &[share], degree, role, output_party_id).await?;
    match res {
        Some(mut r) => Ok(r.pop()),
        _ => Ok(None),
    }
}

pub async fn robust_opens_to<Z: ShamirRing, R: RngCore + Send, B: BaseSessionHandles<R>>(
    session: &B,
    shares: &[Z],
    degree: usize,
    role: &Role,
    output_party_id: usize,
) -> anyhow::Result<Option<Vec<Z>>> {
    session.network().increase_round_counter().await?;
    if role.one_based() == output_party_id {
        let mut set = JoinSet::new();

        //Note: we give the set of corrupt parties as the non_answering_parties argument
        //Thus generic_receive_from_all will not receive from corrupt parties.
        generic_receive_from_all(
            &mut set,
            session,
            role,
            Some(session.corrupt_roles()),
            |msg, _id| match msg {
                NetworkValue::VecRingValue(v) => Ok(v),
                _ => Err(anyhow_error_and_log(
                    "Received something else than a Ring value in robust open to all".to_string(),
                )),
            },
        )?;
        let mut sharings = shares
            .iter()
            .map(|share| ShamirSharing::create(vec![Share::new(*role, *share)]))
            .collect_vec();

        //Note: We are not even considering shares for the already known corrupt parties,
        //thus the effective threshold at this point is the "real" threshold - the number of known corrupt parties
        let threshold = session.threshold() as usize - session.corrupt_roles().len();
        try_reconstruct_from_shares(session, &mut sharings, degree, threshold, &mut set).await
    } else {
        let receiver = session.identity_from(&Role::indexed_by_one(output_party_id))?;

        let networking = Arc::clone(session.network());
        let shares = shares.to_vec();
        let session_id = session.session_id();

        tokio::spawn(async move {
            let _ = networking
                .send(
                    NetworkValue::VecRingValue(shares).to_network(),
                    &receiver,
                    &session_id,
                )
                .await;
        })
        .await?;
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use std::num::Wrapping;

    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{
        algebra::{residue_poly::ResiduePoly, residue_poly::ResiduePoly128},
        execution::{
            runtime::session::{LargeSession, ParameterHandles},
            sharing::{open::robust_opens_to_all, shamir::ShamirSharing},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    #[test]
    fn test_robust_open_all() {
        let parties = 4;
        let threshold = 1;

        async fn task(session: LargeSession) -> Vec<ResiduePoly128> {
            let parties = 4;
            let threshold = 1;
            let num_secrets = 10;
            let mut rng = ChaCha20Rng::seed_from_u64(0);
            let shares = (0..num_secrets)
                .map(|idx| {
                    ShamirSharing::share(
                        &mut rng,
                        ResiduePoly::from_scalar(Wrapping(idx)),
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

        // expect a single round for opening
        let _ =
            execute_protocol_large::<ResiduePoly128, _, _>(parties, threshold, Some(1), &mut task);
    }
}
