use crate::poly::Poly;
use crate::residue_poly::ResiduePoly;
use crate::Sample;
use crate::Z128;
use crate::{One, Zero};
use ndarray::{Array1, Array2};
use rand::RngCore;
use std::num::Wrapping;
use std::ops::{Add, Mul};

pub fn gen_player_share<R: RngCore, Z>(
    rng: &mut R,
    secret: Z,
    threshold: usize,
    player_no: usize,
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
    let share = poly.eval(&ResiduePoly::embed(player_no)?);
    Ok(share)
}

#[derive(Debug)]
pub struct SharedSecretKey {
    pub s: Array1<ResiduePoly<Z128>>,
}

#[derive(Debug)]
pub struct SecretKey {
    s: Array1<Z128>,
}

impl SecretKey {
    pub fn decrypt(&self, ct: &Ciphertext, offset: Z128) -> Z128 {
        let dec = ct.b[0] - ct.a.dot(&self.s);
        dec / offset
    }
}

impl SecretKey {
    fn from_rng<R: RngCore>(rng: &mut R, ell: usize) -> Self {
        let data: Vec<Z128> = (0..ell)
            .map(|_| Wrapping((rng.next_u32() % 2 == 1) as u128))
            .collect();
        SecretKey {
            s: Array1::from_vec(data),
        }
    }
}

pub struct PublicKey {
    mask: Array2<Z128>,
    body: Array2<Z128>,
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
        PublicKey { mask: a, body: b }
    }

    pub fn encrypt<R: RngCore>(&self, rng: &mut R, offset: Z128, message: u8) -> Ciphertext {
        let z = self.mask.nrows();
        let ell = self.mask.ncols();
        let random_coins: Vec<bool> = (0..z).map(|_| rng.next_u32() % 2 == 1).collect();

        let mut a = Array1::<Z128>::zeros(ell);
        let mut b = Array1::from_elem(1, offset * Wrapping(message as u128));

        for (row, coin) in random_coins.iter().enumerate() {
            if *coin {
                a += &self.mask.row(row);
                b += &self.body.row(row);
            }
        }

        Ciphertext { a, b }
    }
}

#[derive(Debug)]
pub struct Ciphertext {
    pub a: Array1<Z128>,
    pub b: Array1<Z128>,
}

pub fn keygen<R: RngCore>(
    rng: &mut R,
    ell: usize,
    player_id: usize,
    threshold: usize,
) -> anyhow::Result<(SharedSecretKey, PublicKey)> {
    let sk = SecretKey::from_rng(rng, ell);
    let pk = PublicKey::from_sk(&sk, rng);

    let shared_sk_bits: Vec<_> =
        sk.s.iter()
            .map(|b| gen_player_share(rng, *b, threshold, player_id).unwrap())
            .collect();

    let shared_sk = SharedSecretKey {
        s: Array1::from_vec(shared_sk_bits),
    };
    Ok((shared_sk, pk))
}
