use crate::algebra::structure_traits::{Ring, ZConsts};
use crate::experimental::algebra::cyclotomic::NewHopeSampler;
use crate::experimental::algebra::cyclotomic::RingElement;
use crate::experimental::algebra::cyclotomic::RqElement;
use crate::experimental::algebra::cyclotomic::TernaryElement;
use crate::experimental::algebra::integers::IntQ;
use crate::experimental::algebra::integers::ModReduction;
use crate::experimental::algebra::integers::PositiveConv;
use crate::experimental::algebra::integers::ZeroCenteredRem;
use crate::experimental::algebra::levels::ScalingFactor;
use crate::experimental::algebra::ntt::Const;
use crate::experimental::algebra::ntt::NTTConstants;
use crypto_bigint::{Limb, NonZero};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Div, Mul, Sub};

pub struct PublicKey<QMod, QRMod, N> {
    pub a: RqElement<QMod, N>,
    pub b: RqElement<QMod, N>,
    pub a_prime: RqElement<QRMod, N>,
    pub b_prime: RqElement<QRMod, N>,
}

#[derive(Debug, Clone)]
pub struct SecretKey {
    pub sk: TernaryElement,
}

pub fn keygen<R, ModQ, ModQR, N>(
    rng: &mut R,
    new_hope_bound: usize,
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

    let sk = TernaryElement::new_hope_sample(rng, 1, degree);
    let sk_mod_q = RqElement::<ModQ, N>::from(sk.clone());
    let sk_mod_qr = RqElement::<ModQR, N>::from(sk.clone());

    let a_mod_q = RqElement::<ModQ, N>::sample_random(rng);
    let e = TernaryElement::new_hope_sample(rng, new_hope_bound, degree);
    let p_mod_q = ModQ::from_u128(plaintext_mod as u128);
    let p_times_e_mod_q = RqElement::<ModQ, N>::from(e) * &p_mod_q;
    let b_mod_q = a_mod_q.clone() * sk_mod_q.clone() + p_times_e_mod_q;

    let r_times_sk_mod_qr = sk_mod_qr.clone() * &ModQR::FACTOR;

    let a_prime_mod_qr = RqElement::<ModQR, N>::sample_random(rng);
    let e_prime = TernaryElement::new_hope_sample(rng, new_hope_bound, degree);
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
pub struct BGVCiphertext<T, N> {
    pub c0: RqElement<T, N>,
    pub c1: RqElement<T, N>,
    pub level: usize,
}

impl<T, N> BGVCiphertext<T, N> {
    fn get_c0(&self) -> &RqElement<T, N> {
        &self.c0
    }

    fn get_c1(&self) -> &RqElement<T, N> {
        &self.c1
    }
}

pub fn bgv_enc<R: Rng + CryptoRng, ModQ, N>(
    rng: &mut R,
    m: &RingElement<u16>,
    pk_a: RqElement<ModQ, N>,
    pk_b: RqElement<ModQ, N>,
    new_hope_bound: usize,
    plaintext_mod: u64,
) -> BGVCiphertext<ModQ, N>
where
    N: Clone + Const,
    N: NTTConstants<ModQ>,
    ModQ: Ring + ZConsts,

    RqElement<ModQ, N>: Add<RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    for<'l, 'r> &'l RqElement<ModQ, N>: Mul<&'r RqElement<ModQ, N>, Output = RqElement<ModQ, N>>,
    for<'r> RqElement<ModQ, N>: Mul<&'r ModQ, Output = RqElement<ModQ, N>>,
{
    let n = N::VALUE;

    let v = RqElement::<ModQ, N>::new_hope_sample(rng, 1, n);
    let e0 = RqElement::<ModQ, N>::new_hope_sample(rng, new_hope_bound, n);
    let e1 = RqElement::<ModQ, N>::new_hope_sample(rng, new_hope_bound, n);

    let p_mod_q = ModQ::from_u128(plaintext_mod as u128);

    let m_mod_q = RqElement::<ModQ, N>::from(
        m.data
            .iter()
            .map(|m| ModQ::from_u128(*m as u128))
            .collect::<Vec<ModQ>>(),
    );

    let mut c0 = &pk_b * &v + e0 * &p_mod_q;
    c0 = c0 + m_mod_q;

    let c1 = &pk_a * &v + e1 * &p_mod_q;

    BGVCiphertext { c0, c1, level: 15 }
}

pub fn bgv_dec<ModQ, N>(
    ct: &BGVCiphertext<ModQ, N>,
    sk: SecretKey,
    p_mod: &NonZero<Limb>,
) -> RingElement<u16>
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
    let supported_ptxt: Vec<u16> = p_red
        .data
        .iter()
        .map(|p| {
            assert!(p < &p_mod);
            p.0 as u16
        })
        .collect();
    RingElement {
        data: supported_ptxt,
    }
}

pub fn modulus_switch<NewQ, ModQ, N>(
    ct: &BGVCiphertext<ModQ, N>,
    q: NewQ,
    big_q: ModQ,
    plaintext_mod: NonZero<Limb>,
) -> BGVCiphertext<NewQ, N>
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

    let a_bar = &aq.div(&big_q_int);
    let b_bar = &bq.div(&big_q_int);

    let d_a = aq - (a_bar * &big_q_int);
    let d_b = bq - (b_bar * &big_q_int);

    let e_a: RingElement<IntQ> = d_a.zero_centered_rem(plaintext_mod).into();
    let e_b: RingElement<IntQ> = d_b.zero_centered_rem(plaintext_mod).into();

    let f_a = a_bar + &e_a;
    let f_b = b_bar + &e_b;

    let a_prime = f_a.mod_reduction();
    let b_prime = f_b.mod_reduction();

    BGVCiphertext {
        c0: RqElement::<NewQ, N>::from(b_prime),
        c1: RqElement::<NewQ, N>::from(a_prime),
        level: 1,
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
        let new_hope_bound = 1;
        let (pk, sk) = keygen::<AesRng, LevelEll, LevelKsw, N65536>(
            &mut rng,
            new_hope_bound,
            PLAINTEXT_MODULUS.get().0,
        );

        let m: Vec<u16> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u16)
            .collect();
        let mr = RingElement::<u16>::from(m);
        let ct = bgv_enc(&mut rng, &mr, pk.a, pk.b, 1, PLAINTEXT_MODULUS.get().0);
        let plaintext = bgv_dec(&ct, sk, &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, mr);
    }

    #[test]
    fn test_bgv_keygen_q1() {
        let mut rng = AesRng::seed_from_u64(0);
        let new_hope_bound = 1;
        let (pk, sk) = keygen::<AesRng, LevelEll, LevelKsw, N65536>(
            &mut rng,
            new_hope_bound,
            PLAINTEXT_MODULUS.get().0,
        );

        let m: Vec<u16> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u16)
            .collect();
        let mr = RingElement::<u16>::from(m);
        let ct = bgv_enc(&mut rng, &mr, pk.a, pk.b, 1, PLAINTEXT_MODULUS.get().0);
        let plaintext = bgv_dec(&ct, sk, &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, mr);
    }

    #[test]
    fn test_big_mod_switch() {
        let mut rng = AesRng::seed_from_u64(0);
        let new_hope_bound = 1;
        let (pk, sk) = keygen::<AesRng, LevelEll, LevelKsw, N65536>(
            &mut rng,
            new_hope_bound,
            PLAINTEXT_MODULUS.get().0,
        );

        let m: Vec<u16> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u16)
            .collect();
        let mr = RingElement::<u16>::from(m);
        let ct = bgv_enc(
            &mut rng,
            &mr,
            pk.a,
            pk.b,
            new_hope_bound,
            PLAINTEXT_MODULUS.get().0,
        );
        let plaintext = bgv_dec(&ct, sk.clone(), &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, mr);

        let q = LevelOne {
            value: GenericModulus(*Q1::MODULUS.as_ref()),
        };
        let big_q = LevelEll {
            value: GenericModulus(*Q::MODULUS.as_ref()),
        };

        let ct_prime =
            modulus_switch::<LevelOne, LevelEll, N65536>(&ct, q, big_q, *PLAINTEXT_MODULUS);
        let plaintext = bgv_dec::<LevelOne, N65536>(&ct_prime, sk, &PLAINTEXT_MODULUS);

        assert_eq!(plaintext, mr);
    }
}
