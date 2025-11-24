use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        poly::Poly,
        structure_traits::{
            BaseRing, ErrorCorrect, Invert, Ring, RingWithExceptionalSequence, Syndrome, Zero,
        },
        syndrome::lagrange_numerators,
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::{
            broadcast::{Broadcast, SyncReliableBroadcast},
            p2p::generic_receive_from_all_senders_with_role_transform,
        },
        config::BatchParams,
        online::preprocessing::BasePreprocessing,
        runtime::{
            party::{Role, TwoSetsRole},
            sessions::base_session::{BaseSessionHandles, GenericBaseSessionHandles},
        },
        sharing::{
            open::{ExternalOpeningInfo, RobustOpen, SecureRobustOpen},
            shamir::ShamirSharings,
            share::Share,
        },
        tfhe_internals::{
            compression_decompression_key::CompressionPrivateKeyShares,
            glwe_key::GlweSecretKeyShare,
            lwe_key::LweSecretKeyShare,
            parameters::{DKGParams, DKGParamsBasics, DkgMode},
            private_keysets::{
                CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, PrivateKeySet,
            },
        },
    },
    networking::value::{BroadcastValue, NetworkValue},
};
use itertools::{izip, Itertools};
use std::{
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet},
    sync::Arc,
};
use tokio::task::JoinSet;
use tracing::instrument;
use zeroize::Zeroize;

pub struct ResharePreprocRequired {
    pub batch_params_128: BatchParams,
    pub batch_params_64: BatchParams,
}

impl ResharePreprocRequired {
    pub fn new_same_set(num_parties: usize, parameters: DKGParams) -> Self {
        let params = parameters.get_params_basics_handle();
        let mut num_randoms_128 = 0;
        let mut num_randoms_64 = 0;

        num_randoms_64 += params.lwe_hat_dimension().0;

        num_randoms_64 += params.lwe_dimension().0;

        match parameters.get_params_basics_handle().get_dkg_mode() {
            DkgMode::Z64 => {
                num_randoms_64 += params.glwe_sk_num_bits() + params.compression_sk_num_bits()
            }
            DkgMode::Z128 => {
                num_randoms_128 += params.glwe_sk_num_bits() + params.compression_sk_num_bits();
                if let DKGParams::WithSnS(p) = parameters {
                    num_randoms_128 += p.glwe_sk_num_bits_sns() + p.sns_compression_sk_num_bits();
                }
            }
        }

        num_randoms_128 *= num_parties;
        num_randoms_64 *= num_parties;

        ResharePreprocRequired {
            batch_params_128: BatchParams {
                triples: 0,
                randoms: num_randoms_128,
            },
            batch_params_64: BatchParams {
                triples: 0,
                randoms: num_randoms_64,
            },
        }
    }
}

// this is the L_i in the spec
fn make_lagrange_numerators<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    sorted_roles: &[Role],
) -> anyhow::Result<Vec<Poly<ResiduePoly<Z, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
{
    // embed party IDs into the ring
    let parties: Vec<_> = sorted_roles
        .iter()
        .map(ResiduePoly::<Z, EXTENSION_DEGREE>::embed_role_to_exceptional_sequence)
        .collect::<Result<Vec<_>, _>>()?;

    // lagrange numerators from Eq.15
    let out = lagrange_numerators(&parties);
    Ok(out)
}

// Define delta_i(Z) = L_i(Z) / L_i(\alpha_i)
// where L_i(Z) = \Pi_{i \ne j} (Z - \alpha_i)
// This function evaluates delta_i(0)
fn delta0i<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    lagrange_numerators: &[Poly<ResiduePoly<Z, EXTENSION_DEGREE>>],
    party_role: &Role,
) -> anyhow::Result<ResiduePoly<Z, EXTENSION_DEGREE>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring + Invert,
{
    let zero = ResiduePoly::<Z, EXTENSION_DEGREE>::get_from_exceptional_sequence(0)?;
    let alphai =
        ResiduePoly::<Z, EXTENSION_DEGREE>::embed_role_to_exceptional_sequence(party_role)?;
    let denom = lagrange_numerators[party_role].eval(&alphai);
    let inv_denom = denom.invert()?;
    Ok(inv_denom * lagrange_numerators[party_role].eval(&zero))
}

#[instrument(
    name = "ReShare (same sets)",
    skip(preproc128, preproc64, session, input_share)
    fields(sid=?session.session_id(),my_role=?session.my_role())
)]
pub async fn reshare_sk_same_sets<
    Ses: BaseSessionHandles,
    P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
    P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
    const EXTENSION_DEGREE: usize,
>(
    preproc128: &mut P128,
    preproc64: &mut P64,
    session: &mut Ses,
    input_share: &mut Option<PrivateKeySet<EXTENSION_DEGREE>>,
    parameters: DKGParams,
) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    // Reshare the GLWE sns key
    let glwe_secret_key_share_sns_as_lwe = if let DKGParams::WithSnS(sns_params) = parameters {
        let expected_key_size = sns_params.glwe_sk_num_bits_sns();
        let maybe_key = input_share.as_mut().and_then(|s| {
            s.glwe_secret_key_share_sns_as_lwe
                .as_mut()
                .map(|key| key.data.as_mut())
        });
        Some(LweSecretKeyShare {
            data: reshare_same_sets(preproc128, session, maybe_key, expected_key_size).await?,
        })
    } else {
        None
    };

    let basic_params_handle = parameters.get_params_basics_handle();

    // Reshare the LWE compute key
    let expected_key_size = basic_params_handle.lwe_dimension().0;
    let maybe_key = input_share
        .as_mut()
        .map(|s| s.lwe_compute_secret_key_share.data.as_mut());
    let lwe_compute_secret_key_share = LweSecretKeyShare {
        data: reshare_same_sets(preproc64, session, maybe_key, expected_key_size).await?,
    };

    // Reshare the LWE PKe key
    let expected_key_size = basic_params_handle.lwe_hat_dimension().0;
    let polynomial_size = basic_params_handle.polynomial_size();
    let maybe_key = input_share
        .as_mut()
        .map(|s| s.lwe_encryption_secret_key_share.data.as_mut());
    let lwe_encryption_secret_key_share = LweSecretKeyShare {
        data: reshare_same_sets(preproc64, session, maybe_key, expected_key_size).await?,
    };

    // Reshare the GLWE compute key
    let expected_key_size = basic_params_handle.glwe_sk_num_bits();
    let glwe_secret_key_share = match parameters.get_params_basics_handle().get_dkg_mode() {
        DkgMode::Z64 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.glwe_secret_key_share
                        .try_cast_mut_to_z64()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            GlweSecretKeyShareEnum::Z64(GlweSecretKeyShare {
                data: reshare_same_sets(preproc64, session, maybe_key, expected_key_size).await?,
                polynomial_size,
            })
        }
        DkgMode::Z128 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.glwe_secret_key_share
                        .try_cast_mut_to_z128()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                data: reshare_same_sets(preproc128, session, maybe_key, expected_key_size).await?,
                polynomial_size,
            })
        }
    };

    // Reshare the GLWE compression key
    let glwe_secret_key_share_compression = if let Some(compression_params) =
        basic_params_handle.get_compression_decompression_params()
    {
        let polynomial_size = compression_params
            .raw_compression_parameters
            .packing_ks_polynomial_size;
        let expected_key_size = basic_params_handle.compression_sk_num_bits();
        Some(match parameters.get_params_basics_handle().get_dkg_mode() {
            DkgMode::Z64 => {
                // Extract the GLWE secret key share for the compression scheme if any
                let maybe_key = input_share
                    .as_mut()
                    .and_then(|s| {
                        s.glwe_secret_key_share_compression
                            .as_mut()
                            .map(|compression_sk_share| {
                                compression_sk_share
                                    .try_cast_mut_to_z64()
                                    .map(|key| key.post_packing_ks_key.data.as_mut())
                            })
                    })
                    .transpose()
                    .map_err(|e| anyhow_error_and_log(e.to_string()))?;
                CompressionPrivateKeySharesEnum::Z64(CompressionPrivateKeyShares {
                    post_packing_ks_key: GlweSecretKeyShare {
                        data: reshare_same_sets(preproc64, session, maybe_key, expected_key_size)
                            .await?,
                        polynomial_size,
                    },
                    params: compression_params.raw_compression_parameters,
                })
            }
            DkgMode::Z128 => {
                // Extract the GLWE secret key share for the compression scheme if any
                let maybe_key = input_share
                    .as_mut()
                    .and_then(|s| {
                        s.glwe_secret_key_share_compression
                            .as_mut()
                            .map(|compression_sk_share| {
                                compression_sk_share
                                    .try_cast_mut_to_z128()
                                    .map(|key| key.post_packing_ks_key.data.as_mut())
                            })
                    })
                    .transpose()
                    .map_err(|e| anyhow_error_and_log(e.to_string()))?;
                CompressionPrivateKeySharesEnum::Z128(CompressionPrivateKeyShares {
                    post_packing_ks_key: GlweSecretKeyShare {
                        data: reshare_same_sets(preproc128, session, maybe_key, expected_key_size)
                            .await?,
                        polynomial_size,
                    },
                    params: compression_params.raw_compression_parameters,
                })
            }
        })
    } else {
        None
    };

    // Reshare the GLWE sns compression key
    let glwe_sns_compression_key_as_lwe = match parameters {
        DKGParams::WithoutSnS(_) => None,
        DKGParams::WithSnS(params_sns) => {
            if params_sns.sns_compression_params.is_some() {
                let expected_key_size = params_sns.compression_sk_num_bits();
                let maybe_key = input_share.as_mut().and_then(|s| {
                    s.glwe_sns_compression_key_as_lwe
                        .as_mut()
                        .map(|key| key.data.as_mut())
                });
                Some(LweSecretKeyShare {
                    data: reshare_same_sets(preproc128, session, maybe_key, expected_key_size)
                        .await?,
                })
            } else {
                None
            }
        }
    };

    Ok(PrivateKeySet {
        lwe_encryption_secret_key_share,
        lwe_compute_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns_as_lwe,
        parameters: basic_params_handle.to_classic_pbs_parameters(),
        glwe_secret_key_share_compression,
        glwe_sns_compression_key_as_lwe,
    })
}

// Note: Can't really split into 2 functions one for sender one for receiver
// because we have parties in both sets.
// We __ALWAYS__ reshare from set1 to set2
pub async fn reshare_two_sets<
    TwoSetsSession: GenericBaseSessionHandles<TwoSetsRole>,
    OneSetSession: BaseSessionHandles,
    P: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
    Z: BaseRing + Zeroize,
    const EXTENSION_DEGREE: usize,
>(
    two_sets_session: &mut TwoSetsSession,
    set_2_session: &mut Option<OneSetSession>,
    preproc: &mut Option<P>,
    input_shares: &mut Option<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    expected_input_len: usize,
) -> anyhow::Result<Option<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    // If I belong to set 2, fetch the masks to send to set 1
    let masks_to_resharers = if two_sets_session.my_role().is_set2() {
        if let Some(preproc) = preproc {
            // setup r_{i,j} shares
            let mut inner_masks_to_resharers = HashMap::new();
            for role in two_sets_session.get_all_sorted_roles() {
                if role.is_set1() {
                    let v = preproc
                        .next_random_vec(expected_input_len)?
                        .into_iter()
                        .map(|v| v.value())
                        .collect_vec();
                    inner_masks_to_resharers.insert(*role, v);
                }
            }
            Some(inner_masks_to_resharers)
        } else {
            return Err(anyhow_error_and_log(
                "Preprocessing is required for parties in set 2 during resharing",
            ));
        }
    } else {
        None
    };

    let external_opening_information = if two_sets_session.my_role().is_set1() {
        // If I belong to set 1, prepare to receive the masks from set 2
        Some(ExternalOpeningInfo::FromSet2(expected_input_len))
    } else {
        None
    };

    // Parties from set_2 open masks to parties in set_1
    let robust_open = SecureRobustOpen::default();
    let masks_opened = robust_open
        .robust_open_list_to_set::<ResiduePoly<Z, EXTENSION_DEGREE>, _>(
            two_sets_session,
            masks_to_resharers.clone(),
            two_sets_session.threshold().threshold_set_2 as usize,
            external_opening_information,
        )
        .await?;

    // Increase round counter on the shared session
    two_sets_session.network().increase_round_counter().await;

    // Parties in set 1 mask their share of the key and send to parties in set 2
    // if ever I am in both sets I remember my own masked share
    let my_masked_shares = if two_sets_session.my_role().is_set1() {
        if let (Some(input_shares), Some(mut rs_opened)) = (input_shares, masks_opened) {
            if input_shares.len() != expected_input_len || rs_opened.len() != expected_input_len {
                return Err(anyhow_error_and_log(format!(
                    "Expected the amount of input shares ({}), the amount of masks ({}) and expected_input_len ({}), to be equal.",
                    input_shares.len(),
                    rs_opened.len(),
                    expected_input_len,
                )));
            }
            let mut vj = Vec::with_capacity(expected_input_len);
            for (r, s) in rs_opened.iter().zip_eq(input_shares.clone()) {
                vj.push(*r + s.value());
            }

            // erase the memory of sk_share and rj
            for share in input_shares {
                share.zeroize();
            }
            for r in &mut rs_opened {
                r.zeroize();
            }

            // Send the masked shares to parties in set 2
            // except myself if I am in both sets
            let values_to_send = Arc::new(NetworkValue::VecRingValue(vj.clone()).to_network());
            for party in two_sets_session.get_all_sorted_roles() {
                if party.is_set2() && party != &two_sets_session.my_role() {
                    two_sets_session
                        .network()
                        .send(Arc::clone(&values_to_send), party)
                        .await?;
                }
            }
            Some(vj)
        } else {
            return Err(anyhow_error_and_log(
                "Input shares and masks are required for parties in set 1 during resharing.",
            ));
        }
    } else {
        None
    };

    // Parties in set 2 receive the masked shares from parties in set 1
    // and finish the resharing
    if two_sets_session.my_role().is_set2() {
        let my_set_session = if let Some(s) = set_2_session {
            s
        } else {
            return Err(anyhow_error_and_log(
                "One-set session is required for parties in set 2 during resharing.",
            ));
        };

        let mut multicast_results = if let Some(my_masked_share) = my_masked_shares {
            let my_role_set_1 = match two_sets_session.my_role() {
                TwoSetsRole::Both(dual_role) => dual_role.role_set_1,
                // We panic here as this must be a bug if we are not in both sets
                _ => panic!("Expected to be in both sets"),
            };
            BTreeMap::from([(my_role_set_1, my_masked_share)])
        } else {
            BTreeMap::new()
        };
        // Receive the masked shares from parties in set 1
        let parties_in_s1 = two_sets_session
            .get_all_sorted_roles()
            .clone()
            .into_iter()
            .filter(|r| r.is_set1())
            .collect();

        let mut jobs = JoinSet::new();
        let transform_s1_to_role = |sender: &TwoSetsRole, _external_opening_info: ()| match sender {
            TwoSetsRole::Set1(role) => *role,
            TwoSetsRole::Both(dual_role) => dual_role.role_set_1,
            // Here it is OK to panic because this function is only called for parties in set 1
            TwoSetsRole::Set2(role) => {
                panic!("Expected to receive from set 1 parties, got {:?}", role)
            }
        };

        generic_receive_from_all_senders_with_role_transform(
            &mut jobs,
            two_sets_session,
            &two_sets_session.my_role(),
            &parties_in_s1,
            Some(two_sets_session.corrupt_roles()),
            |msg, _id| match msg {
                NetworkValue::VecRingValue(v) => Ok(v),
                _ => Err(anyhow_error_and_log(format!(
                    "Received {}, expected a Ring value in robust open to all",
                    msg.network_type_name()
                ))),
            },
            transform_s1_to_role,
            (),
        )
        .await;

        while let Some(res) = jobs.join_next().await {
            let joined_result = if let Ok(v) = res {
                v
            } else {
                tracing::warn!(
                    "During resharing, failed to receive masked share from party in set 1"
                );
                continue;
            };

            match joined_result {
                Ok((role, result)) => {
                    if let Ok(values) = result {
                        multicast_results.insert(role, values);
                    } else {
                        tracing::warn!(
                            "During resharing, failed to receive masked share from party {} in set 1: {}",
                            role,
                            result.err().unwrap()
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("During resharing, Some party has timed out: {}", e);
                }
            }
        }

        let parties_in_s1 = parties_in_s1
            .iter()
            .map(|role| transform_s1_to_role(role, ()))
            .collect::<HashSet<_>>();
        // Make sure I have something to say for all roles in s1, even if it's an empty vec
        for role_in_s1 in parties_in_s1.iter() {
            multicast_results
                .entry(*role_in_s1)
                .or_insert_with(Vec::new);
        }

        // Broadcast those received values within set 2
        let broadcast_results = SyncReliableBroadcast::default()
            .broadcast_from_all(
                my_set_session,
                BroadcastValue::MapRingVector(multicast_results),
            )
            .await?;

        // For each of the received values, take the majority vote

        let mut votes = HashMap::with_capacity(parties_in_s1.len());
        for (sender_in_s2, broadcast_result) in broadcast_results.into_iter() {
            if let BroadcastValue::MapRingVector(mut map_ring_vector) = broadcast_result {
                // We are exploring the purported `multicast_results` receive from `sender_in_s2`
                // and we register its votes
                for role_in_s1 in parties_in_s1.iter() {
                    if let Some(values) = map_ring_vector.remove(role_in_s1) {
                        let candidates_for_role_in_s1 =
                            votes.entry(*role_in_s1).or_insert_with(|| {
                                vec![HashMap::<_, usize>::with_capacity(my_set_session.num_parties()); expected_input_len]
                            });
                        let mut values_iter = values.into_iter();
                        for candidate_for_role_in_s1 in candidates_for_role_in_s1.iter_mut() {
                            if let Some(value) = values_iter.next() {
                                // Using the raw coefs here to be able to use a BinaryHeap later on
                                // so we have a deterministic ordering even if we have equal number of votes
                                *candidate_for_role_in_s1.entry(value.coefs).or_default() +=
                                    1_usize;
                            }
                        }
                    }
                }
            } else {
                tracing::warn!(
                    "During resharing, unexpected broadcast. Adding party {sender_in_s2:?} to corrupt parties"
                );
                my_set_session.add_corrupt(sender_in_s2);
            }
        }

        // Now we take the majority vote for each party in set 1
        let mut agreed_contributions_from_s1 = HashMap::with_capacity(parties_in_s1.len());
        for (role_in_s1, candidates_for_role_in_s1) in votes.into_iter() {
            let mut agreed_values = Vec::with_capacity(expected_input_len);
            for (idx, candidate_for_role_in_s1) in candidates_for_role_in_s1.into_iter().enumerate()
            {
                // Take the max with a deterministic ordering even if there's a tie in votes
                // because it's then ordered on the raw coefficients
                // Note: Heap might be overkill since we only need to track the max...
                let mut heap = BinaryHeap::new();
                for (value, count) in candidate_for_role_in_s1.into_iter() {
                    heap.push((count, value));
                }
                if let Some((count, value)) = heap.pop() {
                    tracing::info!(
                        "During resharing, party {:?} got {} votes for its {idx}th value ",
                        role_in_s1,
                        count,
                    );
                    agreed_values.push(ResiduePoly::from_array(value));
                } else {
                    return Err(anyhow_error_and_log(format!(
                        "During resharing, no majority vote could be found for party {:?}",
                        role_in_s1
                    )));
                }
            }
            agreed_contributions_from_s1.insert(role_in_s1, agreed_values);
        }

        // Compute my share of the unmasked secret
        if let Some(rs_shares) = masks_to_resharers {
            let rs_shares = rs_shares
                .into_iter()
                .map(|(role, value)| (transform_s1_to_role(&role, ()), value))
                .collect::<HashMap<_, _>>();

            let unmasked_reshared_shares = unmask_reshared_shares(
                agreed_contributions_from_s1,
                rs_shares,
                expected_input_len,
            )?;

            // Everything below this should be similar as if we were resharing to same set
            return Ok(Some(
                open_syndromes_and_correct_errors(
                    my_set_session,
                    unmasked_reshared_shares,
                    parties_in_s1.into_iter().collect_vec(),
                    two_sets_session.threshold().threshold_set_1 as usize,
                    expected_input_len,
                )
                .await?,
            ));
        } else {
            return Err(anyhow_error_and_log(
                "Masks from set 2 are required for parties in set 2 during resharing.",
            ));
        };
    }

    Ok(None)
}

pub async fn reshare_same_sets<
    Ses: BaseSessionHandles,
    P: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
    Z: BaseRing + Zeroize,
    const EXTENSION_DEGREE: usize,
>(
    preproc: &mut P,
    session: &mut Ses,
    input_shares: Option<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    expected_input_len: usize,
) -> anyhow::Result<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    // we need share_count shares for every party in the initial set of size n1
    let n1 = session.num_parties();
    let mut all_roles_sorted = session.roles().iter().cloned().collect_vec();
    all_roles_sorted.sort();

    // setup r_{i,j} shares
    let mut masks_to_resharers = HashMap::with_capacity(n1);
    for role in &all_roles_sorted {
        let v = preproc
            .next_random_vec(expected_input_len)?
            .into_iter()
            .map(|v| v.value())
            .collect_vec();
        masks_to_resharers.insert(*role, v);
    }

    // open r_{i,j} to party j
    let mut masks_opened = if let Some(result) = SecureRobustOpen::default()
        .multi_robust_open_list_to(
            session,
            masks_to_resharers.clone(),
            session.threshold() as usize,
        )
        .await?
    {
        result
    } else {
        return Err(anyhow_error_and_log("Failed to robust open r_{i,j}"));
    };

    // opened[0] is r_j
    if masks_opened.len() != expected_input_len {
        return Err(anyhow_error_and_log(format!(
            "Expected the amount of input shares; {}, and openings; {}, to be equal",
            expected_input_len,
            masks_opened.len()
        )));
    }

    // Broadcast our part of the resharing if we have keys to reshare,
    // If we have nothing to reshare, we just broadcast Bot
    let my_broadcast_masked_shares = if let Some(input_shares) = input_shares {
        if input_shares.len() != expected_input_len {
            return Err(anyhow_error_and_log(format!(
                "Expected the amount of input shares ({}), and expected_input_len ({}), to be equal.",
                input_shares.len(),
                expected_input_len,
            )));
        }
        let vj = masks_opened
            .iter()
            .zip_eq(input_shares.clone())
            .map(|(r, s)| *r + s.value())
            .collect_vec();

        // erase the memory of sk_share and rj
        for share in input_shares {
            share.zeroize();
        }
        for r in &mut masks_opened {
            r.zeroize();
        }

        // We are resharing to the same set,
        // so we go straight to the sync-broadcast
        BroadcastValue::RingVector(vj)
    } else {
        BroadcastValue::Bot
    };

    let all_broadcast_masked_shares = SyncReliableBroadcast::default()
        .broadcast_from_all(session, my_broadcast_masked_shares)
        .await?;

    // Process the received broadcasts
    let all_broadcast_masked_shares = all_broadcast_masked_shares
        .into_iter()
        .map(|(role, msg)| {
            if let BroadcastValue::RingVector(v) = msg {
                (role, v)
            } else if let BroadcastValue::Bot = msg {
                tracing::warn!("During resharing, received Bot from {}", role);
                (role, Vec::new())
            } else {
                // Any other variant is malicious behavior
                // since it's broadcast we can add it to malicious parties
                session.add_corrupt(role);
                tracing::error!(
                    "During resharing, unexpected broadcast. Adding {} to corrupt parties",
                    role
                );
                (role, Vec::new())
            }
        })
        .collect::<HashMap<_, _>>();

    let unmasked_reshared_shares = unmask_reshared_shares(
        all_broadcast_masked_shares,
        masks_to_resharers,
        expected_input_len,
    )?;

    open_syndromes_and_correct_errors(
        session,
        unmasked_reshared_shares,
        all_roles_sorted.clone(),
        session.threshold() as usize,
        expected_input_len,
    )
    .await
}

fn unmask_reshared_shares<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    agreed_contributions_from_resharers: HashMap<Role, Vec<ResiduePoly<Z, EXTENSION_DEGREE>>>,
    mut masks_to_resharers: HashMap<Role, Vec<ResiduePoly<Z, EXTENSION_DEGREE>>>,
    expected_input_len: usize,
) -> anyhow::Result<Vec<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    let mut s_share_vec = vec![vec![]; expected_input_len];
    for (resharer_role, vs) in agreed_contributions_from_resharers.into_iter() {
        let rs_share_iter = masks_to_resharers
            .remove(&resharer_role)
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                    "Missing mask share from party {:?} in set 2 during resharing",
                    resharer_role
                ))
            })?
            .clone();
        // rs_share_iter length can be trusted as we generated it ourselves
        // Note: should be equal to expected_input_len
        if vs.len() != rs_share_iter.len() {
            tracing::warn!(
                    "Mistmatch in lengths during resharing: vs.len() = {}, rs_share_iter.len() = {}. Will pad with zeros.",
                    vs.len(),
                    rs_share_iter.len()
                );
        }

        let mut s_share = Vec::with_capacity(expected_input_len);

        for (index, r) in rs_share_iter.into_iter().enumerate() {
            if let Some(v) = vs.get(index) {
                s_share.push(*v - r);
            } else {
                // pad with zero if we don't have enough values
                s_share.push(ResiduePoly::<Z, EXTENSION_DEGREE>::ZERO - r);
            }
        }

        // usually we'd do `s_vec.push((sender, s_share))`
        // but we want to transpose the result so we insert s_share
        // in a "tranposed way"
        // Note that `zip_eq` may panic, but it would imply a bug in this method
        for (v, s) in s_share_vec.iter_mut().zip_eq(s_share) {
            v.push(Share::new(resharer_role, s));
        }
    }

    Ok(s_share_vec)
}
async fn open_syndromes_and_correct_errors<
    Z: BaseRing,
    Ses: BaseSessionHandles,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut Ses,
    unmasked_reshared_shares: Vec<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    resharing_set: Vec<Role>,
    threshold_resharers: usize,
    expected_input_len: usize,
) -> anyhow::Result<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    let resharing_set_sorted = resharing_set.iter().cloned().sorted().collect_vec();
    let num_parties_resharing_set = resharing_set_sorted.len();
    // To avoid calling robust open many times sequentially,
    // we first compute the syndrome shares and then put
    // all the syndrome shares into a n1*share_count vector and call robust open once
    // upon receiving the result we unpack the long vector into a 2D vector
    let mut all_shamir_shares = Vec::with_capacity(expected_input_len);
    let mut all_syndrome_poly_shares =
        Vec::with_capacity(expected_input_len * num_parties_resharing_set);
    for shares in unmasked_reshared_shares {
        let shamir_sharing = ShamirSharings::create(shares);
        let syndrome_share = ResiduePoly::<Z, EXTENSION_DEGREE>::syndrome_compute(
            &shamir_sharing,
            threshold_resharers,
        )?;
        all_shamir_shares.push(shamir_sharing);
        all_syndrome_poly_shares.append(&mut syndrome_share.into_container());
    }

    let all_syndrome_polys = match SecureRobustOpen::default()
        .robust_open_list_to_all(
            session,
            all_syndrome_poly_shares,
            session.threshold() as usize,
        )
        .await?
    {
        Some(xs) => xs,
        None => {
            return Err(anyhow_error_and_log("missing opening".to_string()));
        }
    };

    // now we create chunks from the received syndrome polynomials
    // and create the secret key share
    let mut new_sk_share = Vec::with_capacity(expected_input_len);
    let syndrome_length = num_parties_resharing_set - (threshold_resharers + 1);
    let chunks = all_syndrome_polys.chunks_exact(syndrome_length);
    if chunks.len() != all_shamir_shares.len() {
        return Err(anyhow_error_and_log(format!(
            "Expected the amount of syndrome chunks; {}, and shamir shares; {}, to be equal",
            chunks.len(),
            all_shamir_shares.len()
        )));
    }

    let lagrange_numerators = make_lagrange_numerators(&resharing_set_sorted)?;
    let deltas = resharing_set_sorted
        .iter()
        .map(|role| delta0i(&lagrange_numerators, role))
        .collect::<Result<Vec<_>, _>>()?;

    for (s, shamir_sharing) in chunks.zip_eq(all_shamir_shares) {
        let syndrome_poly = Poly::from_coefs(s.iter().copied().collect_vec());
        let opened_syndrome = ResiduePoly::<Z, EXTENSION_DEGREE>::syndrome_decode(
            syndrome_poly,
            &resharing_set_sorted,
            threshold_resharers,
        )?;

        let res: ResiduePoly<Z, EXTENSION_DEGREE> =
            izip!(shamir_sharing.shares, &deltas, opened_syndrome)
                .map(|(s, d, e)| *d * (s.value() - e))
                .sum();
        new_sk_share.push(Share::new(session.my_role(), res));
    }

    Ok(new_sk_share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z128;
    use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
    use crate::execution::online::preprocessing::RandomPreprocessing;
    use crate::execution::online::triple::open_list;
    use crate::execution::runtime::party::TwoSetsThreshold;
    use crate::execution::runtime::sessions::base_session::{BaseSession, TwoSetsBaseSession};
    use crate::execution::sharing::open::test::deterministically_compute_my_shares;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::execution::tfhe_internals::parameters::{DKGParamsRegular, DKGParamsSnS};
    use crate::execution::tfhe_internals::test_feature::{
        keygen_all_party_shares_from_keyset, KeySet,
    };
    use crate::networking::NetworkMode;
    use crate::tests::helper::tests_and_benches::execute_protocol_two_sets;
    use crate::{
        algebra::structure_traits::Sample,
        error::error_handler::anyhow_error_and_log,
        execution::{
            constants::SMALL_TEST_KEY_PATH,
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::{
                sessions::session_parameters::GenericParameterHandles,
                test_runtime::{generate_fixed_roles, DistributedTestRuntime},
            },
            sharing::shamir::InputOp,
        },
        file_handling::tests::read_element,
        session_id::SessionId,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use std::{collections::HashMap, fmt::Display};
    use tfhe::boolean::prelude::GlweDimension;
    use tfhe::core_crypto::entities::GlweSecretKey;
    use tfhe::shortint::client_key::atomic_pattern::{
        AtomicPatternClientKey, StandardAtomicPatternClientKey,
    };
    use tfhe::shortint::noise_squashing::NoiseSquashingPrivateKey;
    use tfhe::shortint::prelude::ModulusSwitchType;
    use tfhe::shortint::PBSParameters;
    use tfhe::{core_crypto::entities::LweSecretKey, shortint::ClassicPBSParameters};
    use tokio::task::JoinSet;

    fn reconstruct_shares_to_scalar<Z: BaseRing + Display, const EXTENSION_DEGREE: usize>(
        shares: Vec<Vec<ResiduePoly<Z, EXTENSION_DEGREE>>>,
        threshold: usize,
        max_errors: usize,
    ) -> Vec<Z>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
        ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>:
            RevealOp<ResiduePoly<Z, EXTENSION_DEGREE>>,
        ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>: InputOp<ResiduePoly<Z, EXTENSION_DEGREE>>,
    {
        let parties = shares.len();
        let mut out = Vec::with_capacity(shares[0].len());
        for j in 0..shares[0].len() {
            let mut bit_shares = Vec::with_capacity(parties);
            (0..parties).for_each(|i| {
                bit_shares.push(Share::new(
                    Role::indexed_from_zero(i),
                    *shares[i].get(j).unwrap(),
                ));
            });
            let first_bit_sharing = ShamirSharings::create(bit_shares);
            let rec = first_bit_sharing
                .err_reconstruct(threshold, max_errors)
                .unwrap();
            let inner_rec = rec.to_scalar().unwrap();
            out.push(inner_rec)
        }
        out
    }

    fn reconstruct_sk<const EXTENSION_DEGREE: usize>(
        shares: Vec<PrivateKeySet<EXTENSION_DEGREE>>,
        threshold: usize,
        max_errors: usize,
    ) -> (Vec<u128>, Vec<u64>, Vec<u64>)
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        // reconstruct the 128-bit glwe_sns key
        let shares128 = shares
            .iter()
            .map(|x| {
                x.glwe_secret_key_share_sns_as_lwe
                    .clone()
                    .unwrap()
                    .data_as_raw_vec()
            })
            .collect_vec();
        let glwe_sns_sk128 = reconstruct_shares_to_scalar(shares128, threshold, max_errors)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        // reconstruct the 64-bit lwe key
        let shares64 = shares
            .iter()
            .map(|x| x.lwe_compute_secret_key_share.clone().data_as_raw_vec())
            .collect_vec();
        let lwe_sk64 = reconstruct_shares_to_scalar(shares64, threshold, max_errors)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        // reconstruct the glwe key, which may have 64-bit or 128-bit shares
        // so we need to this workaround to handle both cases
        let glwe_sk64 = match shares[0].glwe_secret_key_share {
            GlweSecretKeyShareEnum::Z64(_) => {
                let shares64 = shares
                    .iter()
                    .map(|x| {
                        x.glwe_secret_key_share
                            .clone()
                            .unsafe_cast_to_z64()
                            .data_as_raw_vec()
                    })
                    .collect_vec();
                reconstruct_shares_to_scalar(shares64, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0)
                    .collect_vec()
            }
            GlweSecretKeyShareEnum::Z128(_) => {
                let shares128 = shares
                    .iter()
                    .map(|x| {
                        x.glwe_secret_key_share
                            .clone()
                            .unsafe_cast_to_z128()
                            .data_as_raw_vec()
                    })
                    .collect_vec();
                reconstruct_shares_to_scalar(shares128, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0 as u64)
                    .collect_vec()
            }
        };

        (glwe_sns_sk128, lwe_sk64, glwe_sk64)
    }

    #[test]
    fn reshare_no_error_f4() -> anyhow::Result<()> {
        simulate_reshare::<4>(false, false)
    }

    #[test]
    fn reshare_with_error_f4() -> anyhow::Result<()> {
        simulate_reshare::<4>(true, false)
    }

    #[test]
    fn reshare_with_missing_f4() -> anyhow::Result<()> {
        simulate_reshare::<4>(false, true)
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn reshare_no_error_f3() -> anyhow::Result<()> {
        simulate_reshare::<3>(false, false)
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn reshare_with_error_f3() -> anyhow::Result<()> {
        simulate_reshare::<3>(true, false)
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn reshare_with_missing_f3() -> anyhow::Result<()> {
        simulate_reshare::<3>(false, true)
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn reshare_no_error_f5() -> anyhow::Result<()> {
        simulate_reshare::<5>(false, false)
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn reshare_with_error_f5() -> anyhow::Result<()> {
        simulate_reshare::<5>(true, false)
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn reshare_with_missing_f5() -> anyhow::Result<()> {
        simulate_reshare::<5>(false, true)
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn reshare_no_error_f6() -> anyhow::Result<()> {
        simulate_reshare::<6>(false, false)
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn reshare_with_error_f6() -> anyhow::Result<()> {
        simulate_reshare::<6>(true, false)
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn reshare_with_missing_f6() -> anyhow::Result<()> {
        simulate_reshare::<6>(false, true)
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn reshare_no_error_f7() -> anyhow::Result<()> {
        simulate_reshare::<7>(false, false)
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn reshare_with_error_f7() -> anyhow::Result<()> {
        simulate_reshare::<7>(true, false)
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn reshare_with_missing_f7() -> anyhow::Result<()> {
        simulate_reshare::<7>(false, true)
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn reshare_no_error_f8() -> anyhow::Result<()> {
        simulate_reshare::<8>(false, false)
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn reshare_with_error_f8() -> anyhow::Result<()> {
        simulate_reshare::<8>(true, false)
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn reshare_with_missing_f8() -> anyhow::Result<()> {
        simulate_reshare::<8>(false, true)
    }

    fn simulate_reshare<const EXTENSION_DEGREE: usize>(
        add_error: bool,
        remove_share: bool,
    ) -> anyhow::Result<()>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let num_parties = 7;
        let threshold = 2;

        let mut keyset: KeySet = read_element(std::path::Path::new(SMALL_TEST_KEY_PATH)).unwrap();

        // we make the shares shorter to make sure the test doesn't take too long
        let new_params = truncate_client_keys(&mut keyset);

        // generate the key shares
        let mut rng = AesRng::from_entropy();
        let mut key_shares = keygen_all_party_shares_from_keyset(
            &keyset,
            new_params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();

        let roles = generate_fixed_roles(num_parties);
        //Reshare assumes Sync network
        let mut runtime: DistributedTestRuntime<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            Role,
            EXTENSION_DEGREE,
        > = DistributedTestRuntime::new(roles, threshold as u8, NetworkMode::Sync, None);
        if add_error {
            key_shares[0] = PrivateKeySet {
                lwe_compute_secret_key_share: LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1].lwe_compute_secret_key_share.data.len()
                    ],
                },
                lwe_encryption_secret_key_share: LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1].lwe_encryption_secret_key_share.data.len()
                    ],
                },
                glwe_secret_key_share: match key_shares[0].glwe_secret_key_share {
                    GlweSecretKeyShareEnum::Z64(_) => {
                        GlweSecretKeyShareEnum::Z64(GlweSecretKeyShare {
                            data: vec![
                                Share::new(
                                    Role::indexed_from_zero(0),
                                    ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(&mut rng)
                                );
                                key_shares[1].glwe_secret_key_share.len()
                            ],
                            polynomial_size: key_shares[1].glwe_secret_key_share.polynomial_size(),
                        })
                    }
                    GlweSecretKeyShareEnum::Z128(_) => {
                        GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                            data: vec![
                                Share::new(
                                    Role::indexed_from_zero(0),
                                    ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng)
                                );
                                key_shares[1].glwe_secret_key_share.len()
                            ],
                            polynomial_size: key_shares[1].glwe_secret_key_share.polynomial_size(),
                        })
                    }
                },
                glwe_secret_key_share_sns_as_lwe: Some(LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1]
                            .glwe_secret_key_share_sns_as_lwe
                            .clone()
                            .unwrap()
                            .data
                            .len()
                    ],
                }),
                parameters: key_shares[1].parameters,
                glwe_secret_key_share_compression: key_shares[0]
                    .glwe_secret_key_share_compression
                    .clone(),
                glwe_sns_compression_key_as_lwe: key_shares[0]
                    .glwe_sns_compression_key_as_lwe
                    .clone()
                    .map(|mut inner| {
                        inner.data[0] = Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng),
                        );
                        inner
                    }),
            }
        }
        // sanity check that we can still reconstruct
        let expected_sk = (
            keyset
                .get_raw_glwe_client_sns_key_as_lwe()
                .unwrap()
                .into_container(),
            keyset.get_raw_lwe_client_key().to_owned().into_container(),
            keyset.get_raw_glwe_client_key().to_owned().into_container(),
        );
        // We have at most 1 error, the one we just added
        let rec_sk = reconstruct_sk(key_shares.clone(), threshold, 1);
        assert_eq!(rec_sk, expected_sk);

        runtime.setup_sks(key_shares);

        let session_id = SessionId::from(2);

        let rt = tokio::runtime::Runtime::new()?;
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for role in &runtime.roles {
            let party_keyshare = runtime
                .keyshares
                .clone()
                .map(|ks| ks[role.one_based() - 1].clone())
                .ok_or_else(|| {
                    anyhow_error_and_log("key share not set during decryption".to_string())
                })?;
            let mut session = runtime.large_session_for_party(session_id, *role);

            set.spawn(async move {
                let mut preproc128 =
                    DummyPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(42, &session);
                let mut preproc64 =
                    DummyPreprocessing::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new(42, &session);

                //Testing ResharePreprocRequired
                let preproc_required =
                    ResharePreprocRequired::new_same_set(session.num_parties(), new_params);

                let mut new_preproc_64 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: preproc64
                        .next_random_vec(preproc_required.batch_params_64.randoms)
                        .unwrap(),
                };

                let mut new_preproc_128 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: preproc128
                        .next_random_vec(preproc_required.batch_params_128.randoms)
                        .unwrap(),
                };

                let mut my_contribution =
                    if session.my_role() == Role::indexed_from_zero(0) && remove_share {
                        // simulating a party that lost its key share
                        None
                    } else {
                        Some(party_keyshare)
                    };

                let out = reshare_sk_same_sets(
                    &mut new_preproc_128,
                    &mut new_preproc_64,
                    &mut session,
                    &mut my_contribution,
                    new_params,
                )
                .await
                .unwrap();

                //Making sure ResharPreprocRequired doesn't ask for too much preprocessing
                assert_eq!(new_preproc_64.available_randoms.len(), 0);
                assert_eq!(new_preproc_128.available_randoms.len(), 0);
                (session.my_role(), out, my_contribution)
            });
        }

        let mut results = rt
            .block_on(async {
                let mut results = HashMap::new();
                while let Some(v) = set.join_next().await {
                    let (role, new_share, old_share) = v.unwrap();
                    results.insert(
                        role,
                        (
                            new_share,
                            old_share.map(|osh| osh.glwe_secret_key_share_sns_as_lwe.unwrap()),
                        ),
                    );
                }
                results
            })
            .into_iter()
            .collect_vec();

        // we need to sort by identities and then reconstruct
        results.sort_by(|a, b| a.0.cmp(&(b.0)));
        let (new_shares, old_shares): (Vec<_>, Vec<_>) =
            results.into_iter().map(|(_, b)| b).unzip();
        let actual_sk = reconstruct_sk(new_shares.clone(), threshold, 0);

        // check results
        assert_eq!(actual_sk, expected_sk);

        // Also try to reconstruct with only some shares (including 0 as it's always the corrupt/missing one)
        let partial_shares = new_shares[0..=threshold].to_vec();
        let actual_sk = reconstruct_sk(partial_shares, threshold, 0);
        assert_eq!(actual_sk, expected_sk);

        // check old shares are zero
        for osh in old_shares.into_iter().flatten() {
            osh.data_as_raw_vec()
                .iter()
                .for_each(|x| assert!(x.is_zero()));
        }
        Ok(())
    }

    // We truncate the keys in the keyset to make the test faster
    // We return the params that correspond to the truncated keys
    fn truncate_client_keys(keyset: &mut KeySet) -> DKGParams {
        let (raw_sns_private_key, sns_params) = keyset
            .client_key
            .clone()
            .into_raw_parts()
            .3
            .unwrap()
            .into_raw_parts()
            .into_raw_parts();
        let sns_private_key_len = 8;
        let sns_poly_size = tfhe::shortint::prelude::PolynomialSize(1);
        let new_raw_sns_private_key = GlweSecretKey::from_container(
            raw_sns_private_key.into_container()[..sns_private_key_len].to_vec(),
            sns_poly_size,
        );
        let mut new_sns_params = sns_params;

        match &mut new_sns_params {
            tfhe::shortint::parameters::NoiseSquashingParameters::Classic(
                noise_squashing_classic_parameters,
            ) => {
                noise_squashing_classic_parameters.polynomial_size = sns_poly_size;
                noise_squashing_classic_parameters.glwe_dimension =
                    GlweDimension(sns_private_key_len);
            }
            tfhe::shortint::parameters::NoiseSquashingParameters::MultiBit(
                noise_squashing_multi_bit_parameters,
            ) => {
                noise_squashing_multi_bit_parameters.polynomial_size = sns_poly_size;
                noise_squashing_multi_bit_parameters.glwe_dimension =
                    GlweDimension(sns_private_key_len);
            }
        }
        let new_sns_private_key =
            tfhe::integer::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                NoiseSquashingPrivateKey::from_raw_parts(new_raw_sns_private_key, new_sns_params),
            );

        let (glwe_raw, lwe_raw, params, _) = match keyset
            .client_key
            .to_owned()
            .into_raw_parts()
            .0
            .into_raw_parts()
            .atomic_pattern
        {
            tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey::Standard(
                standard_atomic_pattern_client_key,
            ) => standard_atomic_pattern_client_key.into_raw_parts(),
            tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey::KeySwitch32(_) => {
                panic!("KeySwitch32 is not supported in this test")
            }
        };

        //We update the parameters to match with our truncated keys.
        //In particular we truncate the lwe_key by picking a new lwe_dimension
        //and the glwe_key by picking a new GlweDimension and PolynomialSize
        // and set modulus switch noise reduction to standard
        let test_lwe_dim = params.lwe_dimension().0.min(8);
        let test_glwe_dim = params.glwe_dimension().0.min(1);
        let test_poly_size = params.polynomial_size().0.min(10);
        let new_pbs_params = ClassicPBSParameters {
            lwe_dimension: tfhe::integer::parameters::LweDimension(test_lwe_dim),
            glwe_dimension: tfhe::integer::parameters::GlweDimension(test_glwe_dim),
            polynomial_size: tfhe::integer::parameters::PolynomialSize(test_poly_size),
            lwe_noise_distribution: params.lwe_noise_distribution(),
            glwe_noise_distribution: params.glwe_noise_distribution(),
            pbs_base_log: params.pbs_base_log(),
            pbs_level: params.pbs_level(),
            ks_base_log: params.ks_base_log(),
            ks_level: params.ks_level(),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            max_noise_level: params.max_noise_level(),
            // currently there's no getter for log2_p_fail, so we set it manually
            // doesn't matter what it is
            log2_p_fail: -80.,
            ciphertext_modulus: params.ciphertext_modulus(),
            encryption_key_choice: params.encryption_key_choice(),
            modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
        };

        let lwe_cont: Vec<u64> = lwe_raw.into_container();
        let con = lwe_cont[..test_lwe_dim].to_vec();
        let new_lwe_raw = LweSecretKey::from_container(con);
        let glwe_cont = glwe_raw.into_container();
        let con = glwe_cont[..test_poly_size * test_glwe_dim].to_vec();
        let new_glwe_raw = GlweSecretKey::from_container(
            con,
            tfhe::integer::parameters::PolynomialSize(test_poly_size),
        );

        let sck = StandardAtomicPatternClientKey::from_raw_parts(
            new_glwe_raw,
            new_lwe_raw,
            PBSParameters::PBS(new_pbs_params),
            None,
        );
        let sck = tfhe::shortint::ClientKey {
            atomic_pattern: AtomicPatternClientKey::Standard(sck),
        };
        let sck = tfhe::integer::ClientKey::from_raw_parts(sck);

        let ck = tfhe::ClientKey::from_raw_parts(
            sck,
            None,
            None,
            Some(new_sns_private_key),
            None,
            None,
            tfhe::Tag::default(),
        );
        keyset.client_key = ck;
        DKGParams::WithSnS(DKGParamsSnS {
            regular_params: DKGParamsRegular {
                dkg_mode: DkgMode::Z128,
                sec: 128,
                ciphertext_parameters: new_pbs_params,
                dedicated_compact_public_key_parameters: None,
                compression_decompression_parameters: None,
                cpk_re_randomization_ksk_params: None,
                secret_key_deviations: None,
            },
            sns_params: new_sns_params,
            sns_compression_params: None,
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_reshare_two_sets() {
        let num_parties_s1 = 7;
        let num_parties_s2 = 4;
        let intersection_size = 3;
        let threshold = TwoSetsThreshold {
            threshold_set_1: 2,
            threshold_set_2: 1,
        };

        let num_secrets = 10;

        let mut task = |mut two_sets_session: TwoSetsBaseSession,
                        set_1_session: Option<BaseSession>,
                        mut set_2_session: Option<BaseSession>| async move {
            let s1_roles_cheat = [Role::indexed_from_one(2), Role::indexed_from_one(3)];
            let (mut my_shares, inner_secrets) = if let Some(mut set_1_session) = set_1_session {
                let (inner_secrets, shares) =
                    deterministically_compute_my_shares::<ResiduePolyF4Z128>(
                        num_secrets,
                        set_1_session.my_role(),
                        set_1_session.num_parties(),
                        set_1_session.threshold() as usize,
                        42,
                    );
                let my_role = set_1_session.my_role();
                let my_shares = shares
                    .into_iter()
                    .map(|v| {
                        if s1_roles_cheat.contains(&my_role) {
                            let error = ResiduePolyF4Z128::sample(set_1_session.rng());
                            Share::new(set_1_session.my_role(), v + error)
                        } else {
                            Share::new(set_1_session.my_role(), v)
                        }
                    })
                    .collect_vec();
                (Some(my_shares), Some(inner_secrets))
            } else {
                (None, None)
            };

            let mut preproc = if let Some(set_2_session) = set_2_session.as_ref() {
                let preproc = DummyPreprocessing::<ResiduePolyF4Z128>::new(42, set_2_session);
                Some(preproc)
            } else {
                None
            };

            let reshare_result = reshare_two_sets(
                &mut two_sets_session,
                &mut set_2_session,
                &mut preproc,
                &mut my_shares,
                num_secrets,
            )
            .await;

            if let Some(set_2_session) = set_2_session {
                let reshare_result = reshare_result.unwrap().unwrap();
                let opened_reshared = open_list(&reshare_result, &set_2_session).await.unwrap();
                (two_sets_session.my_role(), opened_reshared)
            } else {
                assert!(reshare_result.unwrap().is_none());
                (two_sets_session.my_role(), inner_secrets.unwrap())
            }
        };

        let mut results = execute_protocol_two_sets::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            num_parties_s1,
            num_parties_s2,
            intersection_size,
            threshold,
            NetworkMode::Sync,
            &mut task,
        )
        .await;

        assert_eq!(
            results.len(),
            num_parties_s2 + num_parties_s1 - intersection_size
        );
        let pivot = results.pop().unwrap();
        for (role, inner_secrets) in results {
            assert_eq!(
                inner_secrets, pivot.1,
                "mismatch between pivot role {} and role {}",
                pivot.0, role
            );
        }
    }
}
