use crate::poly::Poly;
use crate::residue_poly::ResiduePoly;
use crate::Sample;
use crate::Z128;
use crate::{One, Zero};
use ndarray::{Array1, Array2};
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::num::Wrapping;
use std::ops::{Add, Mul};

pub fn gen_single_party_share<R: RngCore, Z>(
    rng: &mut R,
    secret: Z,
    threshold: usize,
    party_id: usize,
) -> anyhow::Result<ResiduePoly<Z>>
where
    Z: Zero + One,
    ResiduePoly<Z>: Add<ResiduePoly<Z>, Output = ResiduePoly<Z>>,
    ResiduePoly<Z>: Mul<ResiduePoly<Z>, Output = ResiduePoly<Z>>,
    Z: Copy,
    Z: Sample,
{
    let embedded_secret = ResiduePoly::from_scalar(secret);
    let poly = Poly::sample_random(rng, embedded_secret, threshold);
    let share = poly.eval(&ResiduePoly::embed(party_id)?);
    Ok(share)
}

#[derive(Debug, Clone)]
pub struct SecretKeyShare {
    pub s: Array1<ResiduePoly<Z128>>,
    pub plaintext_bits: u8,
}

#[derive(Debug, Default)]
pub struct SecretKey {
    pub s: Array1<Z128>,
    plaintext_bits: u8,
}

impl SecretKey {
    pub fn decrypt(&self, ct: &Ciphertext, offset: Z128) -> Z128 {
        let dec = ct.b[0] - ct.a.dot(&self.s);
        dec / offset
    }
}

impl SecretKey {
    fn from_rng<R: RngCore>(rng: &mut R, ell: u32, plaintext_bits: u8) -> Self {
        let data: Vec<Z128> = (0..ell)
            .map(|_| Wrapping((rng.next_u32() % 2 == 1) as u128))
            .collect();
        SecretKey {
            s: Array1::from_vec(data),
            plaintext_bits,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct PublicKey {
    mask: Array2<Z128>,
    body: Array2<Z128>,
    plaintext_bits: u8,
}

impl PublicKey {
    pub fn from_sk<R: RngCore>(sk: &SecretKey, rng: &mut R) -> Self {
        let ell = sk.s.len();
        // TODO(Dragos) this is ok for now, as it is fake preprocessing
        // We might want to modify z in the future with real parameters
        let z = 10;

        let ai: Vec<Z128> = (0..z * ell).map(|_| Z128::sample(rng)).collect();
        let a = Array2::from_shape_vec((z, ell), ai).unwrap();

        let bi = (0..z).map(|j| a.row(j).dot(&sk.s)).collect();
        let b = Array2::from_shape_vec((z, 1), bi).unwrap();
        PublicKey {
            mask: a,
            body: b,
            plaintext_bits: sk.plaintext_bits,
        }
    }

    /// encrypt message using pubkey.
    pub fn encrypt<R: RngCore>(&self, rng: &mut R, message: u8) -> Ciphertext {
        let z = self.mask.nrows();
        let ell = self.mask.ncols();
        let random_coins: Vec<bool> = (0..z).map(|_| rng.next_u32() % 2 == 1).collect();

        let mut a = Array1::<Z128>::zeros(ell);
        let mut b = Array1::from_elem(
            1,
            Wrapping(1_u128 << (127 - self.plaintext_bits)) * Wrapping(message as u128),
        );

        for (row, coin) in random_coins.iter().enumerate() {
            if *coin {
                a += &self.mask.row(row);
                b += &self.body.row(row);
            }
        }

        Ciphertext { a, b }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ciphertext {
    pub a: Array1<Z128>,
    pub b: Array1<Z128>,
}

/// keygen that generates secret key shares for a single given party and a public key
pub fn keygen_single_party_share<R: RngCore>(
    rng: &mut R,
    ell: u32,
    plaintext_bits: u8,
    party_id: usize,
    threshold: usize,
) -> anyhow::Result<(SecretKeyShare, PublicKey)> {
    let sk = SecretKey::from_rng(rng, ell, plaintext_bits);
    let pk = PublicKey::from_sk(&sk, rng);

    let shared_sk_bits: Vec<_> =
        sk.s.iter()
            .map(|b| gen_single_party_share(rng, *b, threshold, party_id).unwrap())
            .collect();

    let shared_sk = SecretKeyShare {
        s: Array1::from_vec(shared_sk_bits),
        plaintext_bits,
    };
    Ok((shared_sk, pk))
}
/// keygen that generates secret key shares for many parties and a public key
pub fn keygen_all_party_shares<R: RngCore>(
    rng: &mut R,
    ell: u32,
    plaintext_bits: u8,
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<(Vec<SecretKeyShare>, PublicKey)> {
    let sk = SecretKey::from_rng(rng, ell, plaintext_bits);
    let pk = PublicKey::from_sk(&sk, rng);

    let mut vv: Vec<Vec<ResiduePoly<Z128>>> = vec![Vec::with_capacity(sk.s.len()); num_parties];

    // for each bit in the secret key generate all parties shares
    for (i, bit) in sk.s.iter().enumerate() {
        let embedded_secret = ResiduePoly::from_scalar(*bit);
        let poly = Poly::sample_random(rng, embedded_secret, threshold);

        for (party_id, v) in vv.iter_mut().enumerate().take(num_parties) {
            v.insert(i, poly.eval(&ResiduePoly::embed(party_id + 1)?));
        }
    }

    // put the individual parties shares into SecretKeyShare structs
    let shared_sks: Vec<_> = (0..num_parties)
        .map(|p| SecretKeyShare {
            s: Array1::from_vec(vv[p].clone()),
            plaintext_bits,
        })
        .collect();

    Ok((shared_sks, pk))
}

/// generic LWE keygen that creates a secret key and a public key
pub fn keygen<R: RngCore>(rng: &mut R, ell: u32, plaintext_bits: u8) -> (SecretKey, PublicKey) {
    let sk = SecretKey::from_rng(rng, ell, plaintext_bits);
    let pk = PublicKey::from_sk(&sk, rng);
    (sk, pk)
}
