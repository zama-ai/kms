use crate::{
    algebra::{
        poly::Poly,
        residue_poly::{ResiduePoly, ResiduePoly128, ResiduePoly64},
        structure_traits::{BaseRing, ErrorCorrect, Invert, RingEmbed, Syndrome},
        syndrome::lagrange_numerators,
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::broadcast_from_all,
        endpoints::keygen::PrivateKeySet,
        online::preprocessing::BasePreprocessing,
        runtime::{party::Role, session::BaseSessionHandles},
        sharing::{
            open::{robust_opens_to, robust_opens_to_all},
            shamir::ShamirSharings,
            share::Share,
        },
        tfhe_internals::{glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare},
    },
    networking::value::BroadcastValue,
};
use itertools::{izip, Itertools};
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
    Rnd: Rng + CryptoRng,
    Ses: BaseSessionHandles<Rnd>,
    P128: BasePreprocessing<ResiduePoly128> + Send,
    P64: BasePreprocessing<ResiduePoly64> + Send,
>(
    preproc128: &mut P128,
    preproc64: &mut P64,
    session: &mut Ses,
    input_share: &mut PrivateKeySet,
) -> anyhow::Result<PrivateKeySet> {
    let glwe_secret_key_share_sns_as_lwe = if let Some(glwe_secret_key_share_sns_as_lwe) =
        input_share.glwe_secret_key_share_sns_as_lwe.as_mut()
    {
        Some(LweSecretKeyShare {
            data: reshare_same_sets(
                preproc128,
                session,
                &mut glwe_secret_key_share_sns_as_lwe.data,
            )
            .await?,
        })
    } else {
        None
    };

    let lwe_secret_key_share = LweSecretKeyShare {
        data: reshare_same_sets(
            preproc64,
            session,
            &mut input_share.lwe_secret_key_share.data,
        )
        .await?,
    };

    let glwe_secret_key_share = GlweSecretKeyShare {
        data: reshare_same_sets(
            preproc64,
            session,
            &mut input_share.glwe_secret_key_share.data,
        )
        .await?,
        polynomial_size: input_share.glwe_secret_key_share.polynomial_size(),
    };
    Ok(PrivateKeySet {
        lwe_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns_as_lwe,
        parameters: input_share.parameters,
    })
}

pub async fn reshare_same_sets<
    Rnd: Rng + CryptoRng,
    Ses: BaseSessionHandles<Rnd>,
    P: BasePreprocessing<ResiduePoly<Z>> + Send,
    Z: BaseRing + Zeroize,
>(
    preproc: &mut P,
    session: &mut Ses,
    input_share: &mut Vec<Share<ResiduePoly<Z>>>,
) -> anyhow::Result<Vec<Share<ResiduePoly<Z>>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    // we need share_count shares for every party in the initial set of size n1
    let n1 = session.num_parties();
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
        .map(|(r, s)| *r + s.value())
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
        let shamir_sharing = ShamirSharings::create(shares);
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
            .map(|(s, d, e)| d * &(s.value() - e))
            .sum();
        new_sk_share.push(Share::new(my_role, res));
    }

    Ok(new_sk_share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::execution::tfhe_internals::test_feature::KeySet;
    use crate::{
        algebra::{
            residue_poly::ResiduePoly128,
            structure_traits::{Sample, Zero},
        },
        error::error_handler::anyhow_error_and_log,
        execution::tfhe_internals::test_feature::keygen_all_party_shares,
        execution::{
            constants::SMALL_TEST_KEY_PATH,
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::{
                session::{LargeSession, ParameterHandles},
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::shamir::InputOp,
        },
        file_handling::read_element,
        session_id::SessionId,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use std::{collections::HashMap, fmt::Display};
    use tfhe::core_crypto::entities::GlweSecretKey;
    use tfhe::{
        core_crypto::entities::LweSecretKey,
        shortint::{ClassicPBSParameters, ShortintParameterSet},
    };
    use tokio::task::JoinSet;

    fn reconstruct_shares_to_scalar<Z: BaseRing + Display>(
        shares: Vec<Vec<ResiduePoly<Z>>>,
        threshold: usize,
    ) -> Vec<Z>
    where
        ShamirSharings<ResiduePoly<Z>>: RevealOp<ResiduePoly<Z>>,
        ShamirSharings<ResiduePoly<Z>>: InputOp<ResiduePoly<Z>>,
    {
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
            let first_bit_sharing = ShamirSharings::create(bit_shares);
            let rec = first_bit_sharing
                .err_reconstruct(threshold, threshold)
                .unwrap();
            let inner_rec = rec.to_scalar().unwrap();
            out.push(inner_rec)
        }
        out
    }

    fn reconstruct_sk(
        shares: Vec<PrivateKeySet>,
        threshold: usize,
    ) -> (Vec<u128>, Vec<u64>, Vec<u64>) {
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
        let glwe_sns_sk128 = reconstruct_shares_to_scalar(shares128, threshold)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        // reconstruct the 64-bit lwe key
        let shares64 = shares
            .iter()
            .map(|x| x.lwe_secret_key_share.clone().data_as_raw_vec())
            .collect_vec();
        let lwe_sk64 = reconstruct_shares_to_scalar(shares64, threshold)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        // reconstruct the 64-bit glwe key
        let shares64 = shares
            .iter()
            .map(|x| x.glwe_secret_key_share.clone().data_as_raw_vec())
            .collect_vec();
        let glwe_sk64 = reconstruct_shares_to_scalar(shares64, threshold)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        (glwe_sns_sk128, lwe_sk64, glwe_sk64)
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
        truncate_client_keys(&mut keyset);

        // generate the key shares
        let mut rng = AesRng::from_entropy();
        let lwe_secret_key = keyset.get_raw_lwe_client_key();
        let glwe_secret_key = keyset.get_raw_glwe_client_key();
        let glwe_secret_key_sns_as_lwe = keyset.sns_secret_key.key.clone();
        let params = keyset.sns_secret_key.params;
        let mut key_shares = keygen_all_party_shares(
            lwe_secret_key,
            glwe_secret_key,
            glwe_secret_key_sns_as_lwe,
            params,
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();

        let identities = generate_fixed_identities(num_parties);
        let mut runtime: DistributedTestRuntime<ResiduePoly128> =
            DistributedTestRuntime::new(identities, threshold as u8);
        if !add_error {
            key_shares[0] = PrivateKeySet {
                lwe_secret_key_share: LweSecretKeyShare {
                    data: vec![
                        Share::new(Role::indexed_by_zero(0), ResiduePoly64::sample(&mut rng));
                        key_shares[1].lwe_secret_key_share.data.len()
                    ],
                },
                glwe_secret_key_share: GlweSecretKeyShare {
                    data: vec![
                        Share::new(Role::indexed_by_zero(0), ResiduePoly64::sample(&mut rng));
                        key_shares[1].glwe_secret_key_share.data.len()
                    ],
                    polynomial_size: key_shares[1].glwe_secret_key_share.polynomial_size,
                },
                glwe_secret_key_share_sns_as_lwe: Some(LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_by_zero(0),
                            ResiduePoly128::sample(&mut rng)
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
            }
        }
        // sanity check that we can still reconstruct
        let expected_sk = (
            keyset.sns_secret_key.key.clone().into_container(),
            keyset.get_raw_lwe_client_key().to_owned().into_container(),
            keyset.get_raw_glwe_client_key().to_owned().into_container(),
        );
        let rec_sk = reconstruct_sk(key_shares.clone(), threshold);
        assert_eq!(rec_sk, expected_sk);

        runtime.setup_sks(key_shares);

        let session_id = SessionId(2);

        let rt = tokio::runtime::Runtime::new()?;
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (index_id, _identity) in runtime.identities.clone().into_iter().enumerate() {
            let mut party_keyshare = runtime
                .keyshares
                .clone()
                .map(|ks| ks[index_id].clone())
                .ok_or_else(|| {
                    anyhow_error_and_log("key share not set during decryption".to_string())
                })?;
            let mut session = runtime.large_session_for_party(session_id, index_id);
            set.spawn(async move {
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
                    results.insert(
                        role,
                        (
                            new_share,
                            old_share.glwe_secret_key_share_sns_as_lwe.unwrap(),
                        ),
                    );
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
        let zero_share = vec![ResiduePoly128::ZERO; old_shares[0].data.len()];
        for old_share in old_shares {
            assert_eq!(old_share.data_as_raw_vec(), zero_share);
        }
        Ok(())
    }

    fn truncate_client_keys(keyset: &mut KeySet) {
        keyset.sns_secret_key.key =
            LweSecretKey::from_container(keyset.sns_secret_key.key.as_ref()[..8].to_vec());
        let (glwe_raw, lwe_raw, params) = keyset
            .client_key
            .to_owned()
            .into_raw_parts()
            .0
            .into_raw_parts()
            .into_raw_parts();

        //We update the parameters to match with our truncated keys.
        //In particular we truncate the lwe_key by picking a new lwe_dimension
        //and the glwe_key by picking a new GlweDimension and PolynomialSize
        let new_pbs_params = ClassicPBSParameters {
            lwe_dimension: tfhe::integer::parameters::LweDimension(8),
            glwe_dimension: tfhe::integer::parameters::GlweDimension(1),
            polynomial_size: tfhe::integer::parameters::PolynomialSize(10),
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
            log2_p_fail: -80.,
            ciphertext_modulus: params.ciphertext_modulus(),
            encryption_key_choice: params.encryption_key_choice(),
        };
        let new_params = ShortintParameterSet::new_pbs_param_set(
            tfhe::shortint::PBSParameters::PBS(new_pbs_params),
        );
        keyset.sns_secret_key.params = new_pbs_params;
        let con: Vec<u64> = lwe_raw.into_container();
        let con = con[..8].to_vec();
        let new_lwe_raw = LweSecretKey::from_container(con);
        let con = glwe_raw.into_container();
        let con = con[..10].to_vec();
        let new_glwe_raw =
            GlweSecretKey::from_container(con, tfhe::integer::parameters::PolynomialSize(10));
        let ck = tfhe::ClientKey::from_raw_parts(
            tfhe::integer::ClientKey::from_raw_parts(tfhe::shortint::ClientKey::from_raw_parts(
                new_glwe_raw,
                new_lwe_raw,
                new_params,
            )),
            None,
        );
        keyset.client_key = ck;
    }
}
