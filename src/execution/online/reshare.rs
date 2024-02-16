use crate::{
    algebra::{
        poly::Poly,
        residue_poly::{ResiduePoly, ResiduePoly128, ResiduePoly64},
        structure_traits::BaseRing,
        syndrome::lagrange_numerators,
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::broadcast_from_all,
        online::preprocessing::Preprocessing,
        runtime::{party::Role, session::BaseSessionHandles},
        sharing::{
            open::{robust_opens_to, robust_opens_to_all},
            shamir::{ShamirRing, ShamirSharing},
            share::Share,
        },
    },
    lwe::SecretKeyShare,
    networking::value::BroadcastValue,
};
use itertools::{izip, Itertools};
use ndarray::Array1;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use zeroize::Zeroize;

// this is the L_i in the spec
fn make_lagrange_numerators<Z: BaseRing>(
    sorted_roles: &[Role],
) -> anyhow::Result<Vec<Poly<ResiduePoly<Z>>>> {
    // embed party IDs into the ring
    let parties: Vec<_> = sorted_roles
        .iter()
        .map(|role| ResiduePoly::<Z>::embed_exceptional_set(role.one_based()))
        .collect::<Result<Vec<_>, _>>()?;

    // lagrange numerators from Eq.15
    let out = lagrange_numerators(&parties);
    Ok(out)
}

// Define delta_i(Z) = L_i(Z) / L_i(\alpha_i)
// where L_i(Z) = \Pi_{i \ne j} (Z - \alpha_i)
// This function evaluates delta_i(0)
fn delta0i<Z: BaseRing>(
    lagrange_numerators: &[Poly<ResiduePoly<Z>>],
    one_based: usize,
) -> anyhow::Result<ResiduePoly<Z>> {
    let zero = ResiduePoly::<Z>::embed_exceptional_set(0)?;
    let alphai = ResiduePoly::<Z>::embed_exceptional_set(one_based)?;
    let denom = lagrange_numerators[one_based - 1].eval(&alphai);
    let inv_denom = denom.invert()?;
    Ok(inv_denom * lagrange_numerators[one_based - 1].eval(&zero))
}

pub async fn reshare_sk_same_sets<
    Rnd: Rng + CryptoRng + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
    P128: Preprocessing<ResiduePoly128> + Send,
    P64: Preprocessing<ResiduePoly64> + Send,
>(
    preproc128: &mut P128,
    preproc64: &mut P64,
    session: &mut Ses,
    input_share: &mut SecretKeyShare,
) -> anyhow::Result<SecretKeyShare> {
    let input_key_share128 =
        reshare_same_sets(preproc128, session, &mut input_share.input_key_share128).await?;
    let input_key_share64 =
        reshare_same_sets(preproc64, session, &mut input_share.input_key_share64).await?;
    Ok(SecretKeyShare {
        input_key_share128,
        input_key_share64,
        threshold_lwe_parameters: input_share.threshold_lwe_parameters,
    })
}

pub async fn reshare_same_sets<
    Rnd: Rng + CryptoRng + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
    P: Preprocessing<ResiduePoly<Z>> + Send,
    Z: BaseRing + Zeroize,
>(
    preproc: &mut P,
    session: &mut Ses,
    input_share: &mut Array1<ResiduePoly<Z>>,
) -> anyhow::Result<Array1<ResiduePoly<Z>>> {
    // we need share_count shares for every party in the initial set of size n1
    let n1 = session.amount_of_parties();
    let share_count = input_share.len(); // this is the lwe dimension if input is sk
    let mut all_roles_sorted = session.role_assignments().keys().copied().collect_vec();
    all_roles_sorted.sort();

    // setup r_{i,j} shares
    let mut rs_shares = HashMap::with_capacity(n1);
    for role in &all_roles_sorted {
        let v = preproc.next_random_vec(share_count)?;
        rs_shares.insert(role, v);
    }

    // open r_{i,j} to party j
    let my_role = session.my_role()?;
    let mut opened = vec![]; // this will be zeroized later
    for other_role in &all_roles_sorted {
        let rs_share = rs_shares
            .get(other_role)
            .ok_or_else(|| anyhow_error_and_log(format!("missing share for {:?}", other_role)))?
            .iter()
            .map(|x| x.value())
            .collect_vec();
        if let Some(res) = robust_opens_to(
            session,
            &rs_share,
            session.threshold() as usize,
            &my_role,
            other_role.one_based(),
        )
        .await?
        {
            opened.push(res)
        }
    }

    // only one r should be opened to us, which we call `rj`
    if opened.len() != 1 {
        return Err(anyhow_error_and_log(format!(
            "expected to only receive exactly one opening but got {}",
            opened.len()
        )));
    }

    // opened[0] is r_j
    let vj = opened[0]
        .iter()
        .zip(input_share.clone())
        .map(|(r, s)| *r + s)
        .collect_vec();

    // erase the memory of sk_share and rj
    for share in input_share {
        share.zeroize();
    }
    for r in &mut opened[0] {
        r.zeroize();
    }

    // sending and receiving the vs (step 3d)
    // is only necessary when the two sets of parties are different
    // so we go straight to the sync-broadcast
    let broadcast_value = BroadcastValue::RingVector(vj.clone());
    let broadcast_result = broadcast_from_all(session, Some(broadcast_value)).await?;

    // compute v_{i,j} - <r_{i,j}>^{S_2}_k, k = 0,1,...,n1-1
    let mut s_share_vec = vec![vec![]; share_count];
    for (sender, msg) in broadcast_result {
        if let BroadcastValue::RingVector(vs) = msg {
            let rs_share_iter = rs_shares
                .get(&sender)
                .ok_or_else(|| anyhow_error_and_log(format!("missing share for {:?}", sender)))?
                .iter()
                .map(|x| x.value());
            let s_share = vs.iter().zip(rs_share_iter).map(|(v, r)| *v - r);

            // usually we'd do `s_vec.push((sender, s_share))`
            // but we want to transpose the result so we insert s_share
            // in a "tranposed way"
            for (v, s) in s_share_vec.iter_mut().zip(s_share) {
                v.push(Share::new(sender, s));
            }
        }
    }

    let lagrange_numerators = make_lagrange_numerators(&all_roles_sorted)?;
    let deltas = all_roles_sorted
        .iter()
        .map(|role| delta0i(&lagrange_numerators, role.one_based()))
        .collect::<Result<Vec<_>, _>>()?;

    // To avoid calling robust open many times sequentially,
    // we first compute the syndrome shares and then put
    // all the syndrome shares into a n1*share_count vector and call robust open once
    // upon receiving the result we unpack the long vector into a 2D vector
    let mut all_shamir_shares = Vec::with_capacity(share_count);
    let mut all_syndrome_poly_shares = Vec::with_capacity(share_count * n1);
    for shares in s_share_vec {
        let shamir_sharing = ShamirSharing::create(shares);
        let mut syndrome_share =
            ResiduePoly::<Z>::syndrome_compute(&shamir_sharing, session.threshold() as usize)?;
        all_shamir_shares.push(shamir_sharing);
        all_syndrome_poly_shares.append(&mut syndrome_share.coefs);
    }

    let all_syndrome_polys = match robust_opens_to_all(
        session,
        &all_syndrome_poly_shares,
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
    let mut new_sk_share = Vec::with_capacity(share_count);
    let syndrome_length = n1 - (session.threshold() as usize + 1);
    let chunks = all_syndrome_polys.chunks_exact(syndrome_length);
    for (s, shamir_sharing) in chunks.zip(all_shamir_shares) {
        let syndrome_poly = Poly::from_coefs(s.iter().copied().collect_vec());
        let opened_syndrome = ResiduePoly::<Z>::syndrome_decode(
            syndrome_poly,
            &all_roles_sorted,
            session.threshold() as usize,
        )?;

        let res: ResiduePoly<Z> = izip!(shamir_sharing.shares, &deltas, opened_syndrome)
            .map(|(s, d, e)| (s.value() - e) * d)
            .sum();
        new_sk_share.push(res);
    }

    Ok(Array1::from_vec(new_sk_share))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, fmt::Display, sync::Arc};

    use aes_prng::AesRng;
    use rand::SeedableRng;
    use tfhe::core_crypto::entities::LweSecretKey;
    use tokio::task::JoinSet;

    use crate::{
        algebra::{
            residue_poly::ResiduePoly128,
            structure_traits::{Sample, Zero},
        },
        computation::SessionId,
        error::error_handler::anyhow_error_and_log,
        execution::constants::SMALL_TEST_KEY_PATH,
        execution::{
            online::preprocessing::DummyPreprocessing,
            runtime::{
                session::{LargeSession, ParameterHandles, SessionParameters},
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeySet, SecretKeyShare},
    };

    fn reconstruct_shares_to_scalar<Z: BaseRing + Display>(
        shares: Vec<Array1<ResiduePoly<Z>>>,
        threshold: usize,
    ) -> Vec<Z> {
        let parties = shares.len();
        let mut out = Vec::with_capacity(shares[0].len());
        for j in 0..shares[0].len() {
            let mut bit_shares = Vec::with_capacity(parties);
            (0..parties).for_each(|i| {
                bit_shares.push(Share::new(
                    Role::indexed_by_zero(i),
                    *shares[i].get(j).unwrap(),
                ));
            });
            let first_bit_sharing = ShamirSharing::create(bit_shares);
            let rec = first_bit_sharing
                .err_reconstruct(threshold, threshold)
                .unwrap();
            let inner_rec = rec.to_scalar().unwrap();
            out.push(inner_rec)
        }
        out
    }

    fn reconstruct_sk(shares: Vec<SecretKeyShare>, threshold: usize) -> (Vec<u128>, Vec<u64>) {
        // reconstruct the 128-bit keys
        let shares128 = shares
            .iter()
            .map(|x| x.input_key_share128.clone())
            .collect_vec();
        let sk128 = reconstruct_shares_to_scalar(shares128, threshold)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        // reconstruct the 64-bit keys
        let shares64 = shares
            .iter()
            .map(|x| x.input_key_share64.clone())
            .collect_vec();
        let sk64 = reconstruct_shares_to_scalar(shares64, threshold)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        (sk128, sk64)
    }

    #[test]
    fn reshare_no_error() -> anyhow::Result<()> {
        simulate_reshare(true)
    }

    #[test]
    fn reshare_with_error() -> anyhow::Result<()> {
        simulate_reshare(false)
    }

    fn simulate_reshare(add_error: bool) -> anyhow::Result<()> {
        let num_parties = 7;
        let threshold = 2;

        let mut keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();

        // we make the shares shorter to make sure the test doesn't take too long
        keyset.sk.lwe_secret_key_128 =
            LweSecretKey::from_container(keyset.sk.lwe_secret_key_128.as_ref()[..8].to_vec());
        keyset.sk.lwe_secret_key_64 =
            LweSecretKey::from_container(keyset.sk.lwe_secret_key_64.as_ref()[..8].to_vec());

        // generate the key shares
        let mut rng = AesRng::from_entropy();
        let mut key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();

        let identities = generate_fixed_identities(num_parties);
        let mut runtime: DistributedTestRuntime<ResiduePoly128> =
            DistributedTestRuntime::new(identities, threshold as u8);
        if !add_error {
            key_shares[0] = SecretKeyShare {
                input_key_share128: Array1::from_vec(vec![
                    ResiduePoly128::sample(&mut rng);
                    key_shares[1].input_key_share128.len()
                ]),
                input_key_share64: Array1::from_vec(vec![
                    ResiduePoly64::sample(&mut rng);
                    key_shares[1].input_key_share64.len()
                ]),
                threshold_lwe_parameters: key_shares[1].threshold_lwe_parameters,
            }
        }
        // sanity check that we can still reconstruct
        let expected_sk = (
            keyset.sk.lwe_secret_key_128.into_container(),
            keyset.sk.lwe_secret_key_64.into_container(),
        );
        let rec_sk = reconstruct_sk(key_shares.clone(), threshold);
        assert_eq!(rec_sk, expected_sk);

        runtime.setup_sks(key_shares);

        let session_id = SessionId(2);

        let rt = tokio::runtime::Runtime::new()?;
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (index_id, identity) in runtime.identities.clone().into_iter().enumerate() {
            let role_assignments = runtime.role_assignments.clone();
            let net = Arc::clone(&runtime.user_nets[index_id]);
            let threshold = runtime.threshold;

            let mut party_keyshare = runtime
                .keyshares
                .clone()
                .map(|ks| ks[index_id].clone())
                .ok_or_else(|| {
                    anyhow_error_and_log("key share not set during decryption".to_string())
                })?;

            set.spawn(async move {
                let session_params = SessionParameters::new(
                    threshold,
                    session_id,
                    identity.clone(),
                    role_assignments,
                )
                .unwrap();
                let mut session = LargeSession::new(session_params, net).unwrap();

                let mut preproc128 =
                    DummyPreprocessing::<ResiduePoly128, AesRng, LargeSession>::new(
                        42,
                        session.clone(),
                    );
                let mut preproc64 = DummyPreprocessing::<ResiduePoly64, AesRng, LargeSession>::new(
                    42,
                    session.clone(),
                );
                let out = reshare_sk_same_sets(
                    &mut preproc128,
                    &mut preproc64,
                    &mut session,
                    &mut party_keyshare,
                )
                .await
                .unwrap();
                (session.my_role().unwrap(), out, party_keyshare)
            });
        }

        let mut results = rt
            .block_on(async {
                let mut results = HashMap::new();
                while let Some(v) = set.join_next().await {
                    let (role, new_share, old_share) = v.unwrap();
                    results.insert(role, (new_share, old_share.input_key_share128));
                }
                results
            })
            .into_iter()
            .collect_vec();

        // we need to sort by identities and then reconstruct
        results.sort_by(|a, b| a.0.zero_based().cmp(&b.0.zero_based()));
        let (new_shares, old_shares): (Vec<_>, Vec<_>) =
            results.into_iter().map(|(_, b)| b).unzip();
        let actual_sk = reconstruct_sk(new_shares, threshold);

        // check results
        assert_eq!(actual_sk, expected_sk);

        // check old shares are zero
        let zero_share = Array1::from_vec(vec![ResiduePoly128::ZERO; old_shares[0].len()]);
        for old_share in old_shares {
            assert_eq!(old_share, zero_share);
        }
        Ok(())
    }
}
