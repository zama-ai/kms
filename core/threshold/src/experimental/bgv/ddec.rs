use itertools::Itertools;
use rand::{CryptoRng, Rng};
use tracing::instrument;

use super::basics::PrivateBgvKeySet;
use super::dkg::BGVShareSecretKey;
use crate::algebra::poly::Poly;
use crate::algebra::structure_traits::ZConsts;
use crate::algebra::structure_traits::{One, Zero};
use crate::execution::runtime::party::Role;
use crate::execution::small_execution::prss::PRSSPrimitives;
use crate::experimental::algebra::cyclotomic::TernaryEntry;
use crate::experimental::algebra::integers::ZeroCenteredRem;
use crate::experimental::bgv::basics::SecretKey;
use crate::experimental::constants::{LOG_B_MULT, LOG_PLAINTEXT, PLAINTEXT_MODULUS};
use crate::experimental::{
    algebra::cyclotomic::{RingElement, RqElement},
    algebra::levels::{LevelEll, LevelOne},
    algebra::ntt::{Const, NTTConstants},
    bgv::basics::LevelledCiphertext,
};
use crate::{
    algebra::structure_traits::FromU128,
    execution::{
        online::triple::open_list, runtime::session::SmallSessionHandles, sharing::share::Share,
    },
    experimental::{
        algebra::integers::IntQ,
        algebra::levels::{CryptoModulus, GenericModulus},
        algebra::ntt::{hadamard_product, ntt_inv, ntt_iter2},
        bgv::basics::modulus_switch,
    },
};

fn partial_decrypt<N: Const + NTTConstants<LevelOne>>(
    c0: &RqElement<LevelOne, N>,
    c1: &RqElement<LevelOne, N>,
    ntt_key: &PrivateBgvKeySet,
) -> Vec<Share<LevelOne>> {
    let owner = ntt_key.as_eval()[0].owner();
    let raw_ntt_key_vec = ntt_key
        .as_eval()
        .iter()
        .map(|ntt_value| ntt_value.value())
        .collect_vec();

    let mut c1_ntt = c1.data.iter().cloned().collect_vec();
    ntt_iter2(&mut c1_ntt, N::VALUE, N::THETA);

    let mut sk_times_c1 = hadamard_product(raw_ntt_key_vec.as_slice(), c1_ntt);
    ntt_inv::<_, N>(&mut sk_times_c1, N::VALUE);
    let sk_times_c1 = RqElement::<_, N>::from(sk_times_c1);

    let res = c0 - &sk_times_c1;
    res.data
        .into_iter()
        .map(|x| Share::new(owner, x))
        .collect_vec()
}
// run decryption with noise flooding
#[instrument(name = "BGV.Threshold-Dec", skip_all,fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub(crate) async fn noise_flood_decryption<
    N: Clone + Const + NTTConstants<LevelOne>,
    S: SmallSessionHandles<LevelOne>,
>(
    session: &mut S,
    keyshares: &PrivateBgvKeySet,
    ciphertext: &LevelledCiphertext<LevelEll, N>,
) -> anyhow::Result<Vec<u32>> {
    let own_role = session.my_role();
    let prss_state = session.prss_as_mut();

    let q = LevelOne {
        value: GenericModulus(*LevelOne::MODULUS.as_ref()),
    };
    let big_q = LevelEll {
        value: GenericModulus(*LevelEll::MODULUS.as_ref()),
    };

    //Scale to level one
    let ct_prime =
        modulus_switch::<LevelOne, LevelEll, N>(ciphertext, q, big_q, *PLAINTEXT_MODULUS);
    let p_share = partial_decrypt(&ct_prime.c0, &ct_prime.c1, keyshares);

    let dist_shift = LevelOne::from_u128(PLAINTEXT_MODULUS.get().into());
    //NOTE: We assumed a power of two cyclotomic ring, so E_M = 1 (Design Decision 24)
    let shifted_t_vec = (0..N::VALUE)
        .map(|_| prss_state.mask_next(own_role, 1u128 << ((LOG_B_MULT - LOG_PLAINTEXT) as u128)))
        .try_collect::<_, Vec<LevelOne>, _>()?
        .into_iter()
        .map(|x| x * dist_shift)
        .collect_vec();

    let c_vec = p_share
        .into_iter()
        .zip(shifted_t_vec)
        .map(|(p_entry, shifted_t_entry)| p_entry + shifted_t_entry)
        .collect_vec();
    let partial_decrypted = open_list(&c_vec, session).await?;
    let reduced = RingElement::<IntQ> {
        data: partial_decrypted.into_iter().map(IntQ::from).collect_vec(),
    }
    .zero_centered_rem(*PLAINTEXT_MODULUS);

    let supported_ptxt: Vec<u32> = reduced
        .data
        .iter()
        .map(|p| {
            assert!(p < &PLAINTEXT_MODULUS);
            p.0 as u32
        })
        .collect();

    Ok(supported_ptxt)
}

pub fn keygen_shares<R: Rng + CryptoRng>(
    rng: &mut R,
    secret_key: &SecretKey,
    num_parties: usize,
    threshold: u8,
) -> Vec<BGVShareSecretKey> {
    let mut all_shares: Vec<BGVShareSecretKey> = vec![
        BGVShareSecretKey {
            sk: Vec::with_capacity(secret_key.sk.data.len())
        };
        num_parties
    ];
    for secret_bit_entry in secret_key.sk.data.iter() {
        let embeded_constant = match *secret_bit_entry {
            TernaryEntry::NegativeOne => LevelOne::MAX,
            TernaryEntry::Zero => LevelOne::ZERO,
            TernaryEntry::PositiveOne => LevelOne::ONE,
        };
        let poly =
            Poly::sample_random_with_fixed_constant(rng, embeded_constant, threshold as usize);
        let mut field_index = LevelOne::ONE;
        for (party_id, shares_per_party) in all_shares.iter_mut().enumerate() {
            shares_per_party.sk.push(Share::new(
                Role::indexed_from_zero(party_id),
                poly.eval(&field_index),
            ));
            field_index += LevelOne::ONE;
        }
    }
    all_shares
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::algebra::structure_traits::One;
    use crate::algebra::structure_traits::Ring;
    use crate::algebra::structure_traits::ZConsts;
    use crate::algebra::structure_traits::Zero;
    use crate::execution::runtime::session::ParameterHandles;
    use crate::execution::runtime::test_runtime::generate_fixed_identities;
    use crate::execution::runtime::test_runtime::DistributedTestRuntime;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::execution::sharing::shamir::ShamirSharings;
    use crate::experimental::algebra::cyclotomic::TernaryEntry;
    use crate::experimental::algebra::levels::LevelKsw;
    use crate::experimental::algebra::levels::LevelOne;
    use crate::experimental::algebra::ntt::Const;
    use crate::experimental::algebra::ntt::N65536;
    use crate::experimental::bgv::basics::bgv_enc;
    use crate::experimental::bgv::basics::keygen;
    use crate::experimental::bgv::ddec::keygen_shares;
    use crate::experimental::bgv::ddec::LevelEll;
    use crate::networking::NetworkMode;
    use crate::session_id::SessionId;
    use aes_prng::AesRng;
    use std::collections::HashMap;
    use tokio::task::JoinSet;

    use itertools::Itertools;
    use rand::{RngCore, SeedableRng};

    use super::*;

    #[test]
    fn test_sharings_sk() {
        let mut rng = AesRng::seed_from_u64(0);

        let (_, sk) =
            keygen::<AesRng, LevelEll, LevelKsw, N65536>(&mut rng, PLAINTEXT_MODULUS.get().0);

        let num_parties = 5;
        let threshold = 1;
        let keyshares = keygen_shares(&mut rng, &sk, num_parties, threshold);
        for bit_idx in 0..N65536::VALUE {
            let kshare = (0..num_parties)
                .map(|i| keyshares[i].sk[bit_idx])
                .collect_vec();
            let ssk = ShamirSharings::create(kshare);
            let b = ssk.reconstruct(threshold as usize).unwrap();
            match sk.sk.data[bit_idx] {
                TernaryEntry::NegativeOne => assert_eq!(b, LevelOne::MAX),
                TernaryEntry::Zero => assert_eq!(b, LevelOne::ZERO),
                TernaryEntry::PositiveOne => assert_eq!(b, LevelOne::ONE),
            }
        }
    }

    #[test]
    fn test_ddec_dummy() {
        let mut rng = AesRng::seed_from_u64(0);

        let (pk, sk) =
            keygen::<AesRng, LevelEll, LevelKsw, N65536>(&mut rng, PLAINTEXT_MODULUS.get().0);

        let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
            .collect();
        let ct = bgv_enc(
            &mut rng,
            &plaintext_vec,
            &pk.a,
            &pk.b,
            PLAINTEXT_MODULUS.get().0,
        );
        let ct = Arc::new(ct);

        let num_parties = 5;
        let threshold = 1;
        let keyshares = keygen_shares(&mut rng, &sk, num_parties, threshold);
        let ntt_keyshares = Arc::new(
            keyshares
                .iter()
                .map(|k| k.as_ntt_repr(N65536::VALUE, N65536::THETA))
                .collect_vec(),
        );

        let identities = generate_fixed_identities(num_parties);
        //This is Async because we only do DDec, which is "online only"
        //Delay P1 by 1s every round
        let delay_map = HashMap::from([(
            identities.first().unwrap().clone(),
            tokio::time::Duration::from_secs(1),
        )]);
        let runtime: DistributedTestRuntime<LevelOne, { LevelOne::EXTENSION_DEGREE }> =
            DistributedTestRuntime::new(identities, threshold, NetworkMode::Async, Some(delay_map));

        let session_id = SessionId::from(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let mut set = JoinSet::new();
        for (index_id, _identity) in runtime.identities.clone().into_iter().enumerate() {
            let mut session = runtime.small_session_for_party(session_id, index_id, None);

            let ksc = Arc::clone(&ntt_keyshares);
            let ctc = Arc::clone(&ct);

            let own_role = Role::indexed_from_zero(index_id);
            let ntt_shares = ksc.as_ref()[index_id]
                .iter()
                .map(|ntt_val| Share::new(own_role, *ntt_val))
                .collect_vec();
            let private_keyset = Arc::new(PrivateBgvKeySet::from_eval_domain(ntt_shares));

            set.spawn(async move {
                let my_role = session.my_role();
                let m = noise_flood_decryption(&mut session, private_keyset.as_ref(), ctc.as_ref())
                    .await
                    .unwrap();
                (my_role, m)
            });
        }

        let results = rt
            .block_on(async {
                let mut results = HashMap::new();
                while let Some(v) = set.join_next().await {
                    let (role, m) = v.unwrap();
                    results.insert(role, m);
                }
                results
            })
            .into_iter()
            .collect_vec();
        let m = results.first().unwrap().1.clone();
        assert_eq!(m, plaintext_vec);
    }
}
