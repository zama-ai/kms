use crate::experimental::algebra::cyclotomic::{NewHopeTernarySampler, RingElement};
use crate::experimental::algebra::integers::{IntQ, PositiveConv, ZeroCenteredRem};
use crate::experimental::algebra::levels::GenericModulus;
use crate::experimental::algebra::levels::{CryptoModulus, ScalingFactor};
use crate::experimental::algebra::ntt::Const;
use crate::experimental::bgv::basics::LevelledCiphertext;
use crate::experimental::bgv::basics::PlaintextVec;
use crate::experimental::constants::{DELTA, PLAINTEXT_MODULUS};
use crate::{
    algebra::structure_traits::FromU128,
    experimental::{
        algebra::{
            cyclotomic::{RqElement, TernaryElement},
            levels::{LevelEll, LevelKsw},
            ntt::N65536,
        },
        bgv::basics::{PrivateBgvKeySet, PublicBgvKeySet, PublicKey, SecretKey},
    },
};
use rand::CryptoRng;
use rand::Rng;

pub type PublicBfvKeySet = PublicKey<LevelEll, LevelKsw, N65536>;
pub type PrivateBfvKeySet = PrivateBgvKeySet;

type PolyDeg = N65536;

pub fn keygen<R>(rng: &mut R) -> (PublicBgvKeySet, SecretKey)
where
    R: Rng + CryptoRng,
{
    let degree = PolyDeg::VALUE;

    let sk = TernaryElement::new_hope_ternary_sample(rng, degree);
    let sk_mod_q = RqElement::<LevelEll, PolyDeg>::from(sk.clone());
    let sk_mod_qr = RqElement::<LevelKsw, PolyDeg>::from(sk.clone());

    let pk_a_mod_q = RqElement::sample_random(rng);
    let e = TernaryElement::new_hope_ternary_sample(rng, degree);
    let e_mod_q = RqElement::<LevelEll, PolyDeg>::from(e);
    let pk_b_mod_q = pk_a_mod_q.clone() * sk_mod_q.clone() + e_mod_q;

    let r_times_sk_mod_qr = sk_mod_qr.clone() * &LevelKsw::FACTOR;

    let pk_a_prime_mod_qr = RqElement::<LevelKsw, PolyDeg>::sample_random(rng);
    let e_prime = TernaryElement::new_hope_ternary_sample(rng, degree);
    let p_mod_qr = LevelKsw::from_u128(u128::from(PLAINTEXT_MODULUS.get()));
    let p_times_e_prime_mod_qr = RqElement::<LevelKsw, PolyDeg>::from(e_prime) * &p_mod_qr;
    let pk_b_prime_mod_qr = pk_a_prime_mod_qr.clone() * sk_mod_qr.clone() + p_times_e_prime_mod_qr
        - r_times_sk_mod_qr * sk_mod_qr;

    (
        PublicKey {
            a: pk_a_mod_q,
            b: pk_b_mod_q,
            a_prime: pk_a_prime_mod_qr,
            b_prime: pk_b_prime_mod_qr,
        },
        SecretKey { sk },
    )
}

pub fn bfv_enc<R: Rng + CryptoRng>(
    rng: &mut R,
    m: &PlaintextVec,
    pk_a: &RqElement<LevelEll, PolyDeg>,
    pk_b: &RqElement<LevelEll, PolyDeg>,
) -> LevelledCiphertext<LevelEll, PolyDeg>
where
{
    let n = PolyDeg::VALUE;

    let v = RqElement::new_hope_ternary_sample(rng, n);
    let e0 = RqElement::new_hope_ternary_sample(rng, n);
    let e1 = RqElement::new_hope_ternary_sample(rng, n);

    // let delta = (q-1) / p;

    let m_times_delta = RqElement::<LevelEll, PolyDeg>::from(
        m.iter()
            .map(|m| LevelEll::from_u128(*m as u128) * *DELTA)
            .collect::<Vec<LevelEll>>(),
    );

    let c0 = pk_b * &v + e0 + m_times_delta;
    let c1 = pk_a * &v + e1;

    LevelledCiphertext { c0, c1 }
}

pub fn bfv_dec(ct: &LevelledCiphertext<LevelEll, PolyDeg>, sk: SecretKey) -> PlaintextVec {
    let sk_mod_q = RqElement::<LevelEll, PolyDeg>::from(sk.sk);
    let pdec = ct.get_c0() - &(ct.get_c1() * sk_mod_q);
    let pdec_int = RingElement::<IntQ>::from(pdec);
    let p_mod = IntQ::from(PLAINTEXT_MODULUS.0);
    let pdec_times_p_mod = pdec_int * p_mod;
    let q_ell = LevelEll {
        value: GenericModulus(*LevelEll::MODULUS.as_ref()),
    };
    let q_ell_int = IntQ::from_non_centered(&q_ell);
    let m = &pdec_times_p_mod.round(&q_ell_int);
    let m = m.zero_centered_rem(*PLAINTEXT_MODULUS);
    let supported_ptxt: Vec<u32> = m
        .data
        .iter()
        .map(|p| {
            assert!(p < &PLAINTEXT_MODULUS);
            p.0 as u32
        })
        .collect();
    supported_ptxt
}

pub fn bfv_to_bgv(
    ct: LevelledCiphertext<LevelEll, PolyDeg>,
) -> LevelledCiphertext<LevelEll, PolyDeg> {
    let p_mod_ell = LevelEll::from_u128(u128::from(PLAINTEXT_MODULUS.get()));
    let neg_p_mod_ell = -p_mod_ell;
    let c0 = ct.c0 * &neg_p_mod_ell;
    let c1 = ct.c1 * &neg_p_mod_ell;

    LevelledCiphertext { c0, c1 }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::execution::runtime::test_runtime::generate_fixed_identities;
    use crate::experimental::algebra::ntt::NTTConstants;
    use crate::experimental::bgv::ddec::keygen_shares;
    use crate::experimental::bgv::endpoints::threshold_decrypt;
    use crate::experimental::bgv::runtime::BGVTestRuntime;
    use crate::experimental::{bgv::basics::bgv_dec, constants::PLAINTEXT_MODULUS};
    use crate::networking::NetworkMode;
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_bfv_keygen() {
        let mut rng = AesRng::seed_from_u64(0);
        let (pk, sk) = keygen::<AesRng>(&mut rng);

        let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
            .collect();
        let ct = bfv_enc(&mut rng, &plaintext_vec, &pk.a, &pk.b);
        let plaintext = bfv_dec(&ct, sk);
        assert_eq!(plaintext, plaintext_vec);
    }

    #[test]
    fn test_bfv_to_bgv() {
        let mut rng = AesRng::seed_from_u64(0);
        let (pk, sk) = keygen::<AesRng>(&mut rng);

        let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
            .collect();
        let ct = bfv_enc(&mut rng, &plaintext_vec, &pk.a, &pk.b);
        let bgv_ct = bfv_to_bgv(ct);

        let plaintext_from_bgv = bgv_dec(&bgv_ct, sk, &PLAINTEXT_MODULUS);
        assert_eq!(plaintext_from_bgv, plaintext_vec);
    }

    #[test]
    fn test_threshold_bfv() {
        let mut rng = AesRng::seed_from_u64(0);
        let (pk, sk) = keygen::<AesRng>(&mut rng);

        let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
            .collect();
        let ct = bfv_enc(&mut rng, &plaintext_vec, &pk.a, &pk.b);
        let bgv_ct = bfv_to_bgv(ct);

        let n = 4;
        let t = 1;
        let keyshares = keygen_shares(&mut rng, &sk, n, t);
        let ntt_keyshares: Vec<_> = keyshares
            .iter()
            .map(|k| k.as_ntt_repr(N65536::VALUE, N65536::THETA))
            .collect();
        let identities = generate_fixed_identities(n);
        //Delay P1 by 1s every round
        let delay_map = HashMap::from([(
            identities.first().unwrap().clone(),
            std::time::Duration::from_secs(1),
        )]);
        let runtime =
            BGVTestRuntime::new(identities.clone(), t, NetworkMode::Async, Some(delay_map));
        let outputs = threshold_decrypt(&runtime, &ntt_keyshares, &bgv_ct).unwrap();
        let out_dec = outputs[&identities[0]].clone();
        assert_eq!(out_dec, plaintext_vec);
    }
}
