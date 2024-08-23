use crate::algebra::structure_traits::{Ring, ZConsts};
use crate::execution::sharing::share::Share;
use crate::experimental::algebra::cyclotomic::NewHopeTernarySampler;
use crate::experimental::algebra::cyclotomic::RingElement;
use crate::experimental::algebra::cyclotomic::RqElement;
use crate::experimental::algebra::cyclotomic::TernaryElement;
use crate::experimental::algebra::integers::IntQ;
use crate::experimental::algebra::integers::ModReduction;
use crate::experimental::algebra::integers::PositiveConv;
use crate::experimental::algebra::integers::ZeroCenteredRem;
use crate::experimental::algebra::levels::{LevelEll, LevelKsw, LevelOne, ScalingFactor};
use crate::experimental::algebra::ntt::ntt_iter2;
use crate::experimental::algebra::ntt::NTTConstants;
use crate::experimental::algebra::ntt::{Const, N65536};
use crate::experimental::constants::PLAINTEXT_MODULUS;
use crypto_bigint::{Limb, NonZero};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Sub};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKey<QMod, QRMod, N> {
    pub a: RqElement<QMod, N>,
    pub b: RqElement<QMod, N>,
    pub a_prime: RqElement<QRMod, N>,
    pub b_prime: RqElement<QRMod, N>,
}

pub type PublicBgvKeySet = PublicKey<LevelEll, LevelKsw, N65536>;
pub type PlaintextVec = Vec<u32>;
pub type LevelEllCiphertext = LevelledCiphertext<LevelEll, N65536>;

#[derive(Debug, Clone)]
pub struct SecretKey {
    pub sk: TernaryElement,
}

/// Set of BGV key shares. Note that the key shares are stored in NTT form.
#[derive(Clone)]
pub struct PrivateBgvKeySet {
    lwe_sk: Vec<Share<LevelOne>>,
}

impl PrivateBgvKeySet {
    // Construct a set of BGV key shares given key shares from a BGV key in polynomial form.
    pub fn from_poly_representation(key_shares: Vec<Share<LevelOne>>) -> Self {
        let owner = key_shares[0].owner();
        let mut csk = key_shares
            .iter()
            .map(|poly_share| poly_share.value())
            .collect_vec();
        ntt_iter2(&mut csk, N65536::VALUE, N65536::THETA);
        let lwe_shares = csk
            .iter()
            .map(|ntt_share| Share::new(owner, *ntt_share))
            .collect_vec();
        PrivateBgvKeySet { lwe_sk: lwe_shares }
    }

    // Construct a set of BGV key shares given the key shares from a BGV key in NTT form.
    pub fn from_eval_domain(key_shares: Vec<Share<LevelOne>>) -> Self {
        PrivateBgvKeySet { lwe_sk: key_shares }
    }

    pub fn as_eval(&self) -> &Vec<Share<LevelOne>> {
        &self.lwe_sk
    }
}

pub fn keygen<R, ModQ, ModQR, N>(
    rng: &mut R,
    plaintext_mod: u64,
) -> (PublicKey<ModQ, ModQR, N>, SecretKey)
where
    R: Rng + CryptoRng,
    N: Clone + Const,
    ModQ: ZConsts,
    ModQ: Ring,
    ModQR: ZConsts,
    ModQR: Ring,
    ModQR: ScalingFactor,
    N: NTTConstants<ModQ>,
    RqElement<ModQ, N>: Add<RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    RqElement<ModQ, N>: Sub<RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    RqElement<ModQ, N>: Mul<RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    RqElement<ModQR, N>: Add<RqElement<ModQR, N>, Output = RqElement<ModQR, N>>,
    RqElement<ModQR, N>: Sub<RqElement<ModQR, N>, Output = RqElement<ModQR, N>>,
    RqElement<ModQR, N>: Mul<RqElement<ModQR, N>, Output = RqElement<ModQR, N>>,
    for<'r> RqElement<ModQ, N>: Mul<&'r ModQ, Output = RqElement<ModQ, N>>,
    for<'r> RqElement<ModQR, N>: Mul<&'r ModQR, Output = RqElement<ModQR, N>>,
{
    let degree = N::VALUE;

    let sk = TernaryElement::new_hope_ternary_sample(rng, degree);
    let sk_mod_q = RqElement::<ModQ, N>::from(sk.clone());
    let sk_mod_qr = RqElement::<ModQR, N>::from(sk.clone());

    let a_mod_q = RqElement::<ModQ, N>::sample_random(rng);
    let e = TernaryElement::new_hope_ternary_sample(rng, degree);
    let p_mod_q = ModQ::from_u128(plaintext_mod as u128);
    let p_times_e_mod_q = RqElement::<ModQ, N>::from(e) * &p_mod_q;
    let b_mod_q = a_mod_q.clone() * sk_mod_q.clone() + p_times_e_mod_q;

    let r_times_sk_mod_qr = sk_mod_qr.clone() * &ModQR::FACTOR;

    let a_prime_mod_qr = RqElement::<ModQR, N>::sample_random(rng);
    let e_prime = TernaryElement::new_hope_ternary_sample(rng, degree);
    let p_mod_qr = ModQR::from_u128(plaintext_mod as u128);
    let p_times_e_prime_mod_qr = RqElement::<ModQR, N>::from(e_prime) * &p_mod_qr;
    let b_prime_mod_qr = a_prime_mod_qr.clone() * sk_mod_qr.clone() + p_times_e_prime_mod_qr
        - r_times_sk_mod_qr * sk_mod_qr;

    (
        PublicKey {
            a: a_mod_q,
            b: b_mod_q,
            a_prime: a_prime_mod_qr,
            b_prime: b_prime_mod_qr,
        },
        SecretKey { sk },
    )
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LevelledCiphertext<T, N> {
    pub c0: RqElement<T, N>,
    pub c1: RqElement<T, N>,
}

impl<T, N> LevelledCiphertext<T, N> {
    pub fn get_c0(&self) -> &RqElement<T, N> {
        &self.c0
    }

    pub fn get_c1(&self) -> &RqElement<T, N> {
        &self.c1
    }
}

pub fn bgv_pk_encrypt<R: Rng + CryptoRng>(
    rng: &mut R,
    m: &PlaintextVec,
    pk: &PublicBgvKeySet,
) -> LevelEllCiphertext {
    bgv_enc::<R, LevelEll, N65536>(rng, m, &pk.a, &pk.b, PLAINTEXT_MODULUS.0)
}

pub fn bgv_enc<R: Rng + CryptoRng, ModQ, N>(
    rng: &mut R,
    m: &PlaintextVec,
    pk_a: &RqElement<ModQ, N>,
    pk_b: &RqElement<ModQ, N>,
    plaintext_mod: u64,
) -> LevelledCiphertext<ModQ, N>
where
    N: Clone + Const,
    N: NTTConstants<ModQ>,
    ModQ: Ring + ZConsts,

    RqElement<ModQ, N>: Add<RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    for<'l, 'r> &'l RqElement<ModQ, N>: Mul<&'r RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    for<'r> RqElement<ModQ, N>: Mul<&'r ModQ, Output = RqElement<ModQ, N>>,
{
    let n = N::VALUE;

    let v = RqElement::<ModQ, N>::new_hope_ternary_sample(rng, n);
    let e0 = RqElement::<ModQ, N>::new_hope_ternary_sample(rng, n);
    let e1 = RqElement::<ModQ, N>::new_hope_ternary_sample(rng, n);

    let p_mod_q = ModQ::from_u128(plaintext_mod as u128);

    let m_mod_q = RqElement::<ModQ, N>::from(
        m.iter()
            .map(|m| ModQ::from_u128(*m as u128))
            .collect::<Vec<ModQ>>(),
    );

    let mut c0 = pk_b * &v + e0 * &p_mod_q;
    c0 = c0 + m_mod_q;

    let c1 = pk_a * &v + e1 * &p_mod_q;

    LevelledCiphertext { c0, c1 }
}

pub fn bgv_dec<ModQ, N>(
    ct: &LevelledCiphertext<ModQ, N>,
    sk: SecretKey,
    p_mod: &NonZero<Limb>,
) -> PlaintextVec
where
    N: Const,
    N: NTTConstants<ModQ>,
    ModQ: Ring,
    RqElement<ModQ, N>: From<TernaryElement>,
    IntQ: From<ModQ>,
    IntQ: Into<u64>,
    for<'l> &'l RqElement<ModQ, N>: Mul<RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    for<'l, 'r> &'l RqElement<ModQ, N>: Sub<&'r RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    for<'l> &'l RqElement<ModQ, N>: Mul<RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
{
    let sk_mod_q = RqElement::<ModQ, N>::from(sk.sk);
    let p = ct.get_c0() - &(ct.get_c1() * sk_mod_q);
    // reinterpret this as integer over (-p/2, p/2] and do the final plaintext reduction p_mod.
    let p_red = RingElement::<IntQ>::from(p).zero_centered_rem(*p_mod);
    let supported_ptxt: Vec<u32> = p_red
        .data
        .iter()
        .map(|p| {
            assert!(p < p_mod);
            p.0 as u32
        })
        .collect();
    supported_ptxt
}

pub fn modulus_switch<NewQ, ModQ, N>(
    ct: &LevelledCiphertext<ModQ, N>,
    q: NewQ,
    big_q: ModQ,
    plaintext_mod: NonZero<Limb>,
) -> LevelledCiphertext<NewQ, N>
where
    IntQ: From<ModQ>,
    IntQ: PositiveConv<ModQ>,
    IntQ: PositiveConv<NewQ>,

    for<'a> RingElement<IntQ>: From<&'a RqElement<ModQ, N>>,
    RingElement<IntQ>: ModReduction<NewQ, Output = RingElement<NewQ>>,
    RingElement<IntQ>: Mul<IntQ, Output = RingElement<IntQ>>,
    RingElement<IntQ>: Sub<RingElement<IntQ>, Output = RingElement<IntQ>>,

    N: Const,
    RqElement<NewQ, N>: From<RingElement<NewQ>>,
    RqElement<NewQ, N>: Clone,
{
    let (a, b) = (ct.get_c1(), ct.get_c0());
    let a_int = RingElement::<IntQ>::from(a);
    let b_int = RingElement::<IntQ>::from(b);

    let big_q_int = IntQ::from_non_centered(&big_q);
    let q_int = IntQ::from_non_centered(&q);

    let aq = a_int * q_int;
    let bq = b_int * q_int;

    let a_bar = &aq.div_and_round(&big_q_int);
    let b_bar = &bq.div_and_round(&big_q_int);

    let d_a = aq - (a_bar * &big_q_int);
    let d_b = bq - (b_bar * &big_q_int);

    let e_a: RingElement<IntQ> = d_a.zero_centered_rem(plaintext_mod).into();
    let e_b: RingElement<IntQ> = d_b.zero_centered_rem(plaintext_mod).into();

    let f_a = a_bar + &e_a;
    let f_b = b_bar + &e_b;

    let a_prime = f_a.mod_reduction();
    let b_prime = f_b.mod_reduction();

    LevelledCiphertext {
        c0: RqElement::<NewQ, N>::from(b_prime),
        c1: RqElement::<NewQ, N>::from(a_prime),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experimental::algebra::levels::{
        GenericModulus, LevelEll, LevelKsw, LevelOne, Q, Q1,
    };
    use crate::experimental::algebra::ntt::N65536;
    use crate::experimental::constants::PLAINTEXT_MODULUS;
    use aes_prng::AesRng;
    use crypto_bigint::modular::ConstMontyParams;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_bgv_keygen() {
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
        let plaintext = bgv_dec(&ct, sk, &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, plaintext_vec);
    }

    #[test]
    fn test_bgv_keygen_q1() {
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
        let plaintext = bgv_dec(&ct, sk, &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, plaintext_vec);
    }

    #[test]
    fn test_big_mod_switch() {
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
        let plaintext = bgv_dec(&ct, sk.clone(), &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, plaintext_vec);

        let q = LevelOne {
            value: GenericModulus(*Q1::MODULUS.as_ref()),
        };
        let big_q = LevelEll {
            value: GenericModulus(*Q::MODULUS.as_ref()),
        };

        let ct_prime =
            modulus_switch::<LevelOne, LevelEll, N65536>(&ct, q, big_q, *PLAINTEXT_MODULUS);
        let plaintext = bgv_dec::<LevelOne, N65536>(&ct_prime, sk, &PLAINTEXT_MODULUS);

        assert_eq!(plaintext, plaintext_vec);
    }
}
