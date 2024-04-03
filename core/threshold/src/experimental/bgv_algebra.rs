use crate::algebra::gf256::error_correction;
use crate::algebra::poly::lagrange_polynomials;
use crate::algebra::poly::Poly;
use crate::algebra::structure_traits::ErrorCorrect;
use crate::algebra::structure_traits::FromU128;
use crate::algebra::structure_traits::Ring;
use crate::algebra::structure_traits::RingEmbed;
use crate::algebra::structure_traits::ZConsts;
use crate::algebra::structure_traits::{Field, One, Sample, Zero};
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::sharing::shamir::ShamirSharing;
use crate::execution::sharing::shamir::ShamirSharings;
use crypto_bigint::impl_modulus;
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::Encoding;
use crypto_bigint::Odd;
use crypto_bigint::RandomMod;
use crypto_bigint::Uint;
use crypto_bigint::U1536;
use crypto_bigint::{U128, U768};
use lazy_static::lazy_static;
use rand::CryptoRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::sync::RwLock;

// These are the three moduli used in BGV/BGV: Q1, Q, QR.
// See NIST doc for more information.
// log_2(Q1)~ 92, log_2(Q)~ 742, log_2(QR)~1493
// The modulus Q1 is the modulus where all ciphertexts have to lie after modulus switching a ciphertext.
// Basically once a ciphertext has reached modulus Q1 then it is ready to apply the
// PRSS mask and do a partial decryption followed by a robust opening.
// The modulus Q = prod(Q1,...,Q_ell) where each Q_i~2^{46}, i > 1
// The modulus QR = Q * R is used for key switching, but never used for ddec.
//
// Note that each modulus is coprime with 2 * N and P where N is the number of slots and P is the plaintext modulus
// The modulus restriction being coprime with 2N ensures that there is a primitive root of order 2N, ie there is a x such that x^2N = 1 mod Q
// Having such a root makes it easy to compute NTT over Q to support fast multiplication.
impl_modulus!(Q1, U128, "00000000100010000000002c002c0001");
impl_modulus!(Q, U768, "000000013355477e91f38705fa80df474d509fa966146c31d5f49736641be9317e77b16ec3619bd8ba71189114d10d908b63d80f63622d3b5be88e621c1f50977b47d27011bac33a104d116606db87cb392a4d10e672c7f1f8ce98198bf60001");
impl_modulus!(QR, U1536, "0000000000004cd59eb4f65c863e6061b6720b25fb3e816f749190899b4abed4935359ea4bf99d3417ce959274c08b588898663d18dccedc64276248fa92aaa05b2db2f7d36df90ab53d34e1c86cc61063a9b03d618ecce0eb993030243a0de47250bca4d2dabd1cc5c8443b23b396fea076dd16222feaced44ea1ab836e816c0cfa8e6d4f4ad4b1191cc50e75a511b208bf580c8549fc9009b234fe574b0ba66948f50b66b3aacc9aa096d5ec4cd84c801ec65ff4bf770477f7338990060001");

#[derive(Hash, Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct GenericModulus<const LIMBS: usize>(pub Uint<LIMBS>);

pub type LevelOne = GenericModulus<{ U128::LIMBS }>;
pub type LevelEll = GenericModulus<{ U768::LIMBS }>;
pub type LevelKsw = GenericModulus<{ U1536::LIMBS }>;

type ConstMontyFormQ1 = crypto_bigint::modular::ConstMontyForm<Q1, { U128::LIMBS }>;
type ConstMontyFormQ = crypto_bigint::modular::ConstMontyForm<Q, { U768::LIMBS }>;
type ConstMontyFormQR = crypto_bigint::modular::ConstMontyForm<QR, { U1536::LIMBS }>;

/// Basic moduli trait for data mod Q, to avoid code duplication.
pub trait CryptoModulus {
    /// This makes easy to grab the underlying crypto_bigint type
    type Modulus;
    /// This makes it easy to grab the Odd<_> version of the underlying crypto_bigint type.
    type OddModulus;
    /// Type used for accessing custom montgomery multiplication from bigint library.
    type ConstMontyForm;
    /// The modulus in which operations are performed, retrieved from the impl_modulus macro.
    const R: Self::OddModulus;
    /// Perform montgomery multiplication modulo R.
    fn monty_mul(&self, y: &Self) -> Self;
    /// Retrieve reference from inner bigint type.
    fn as_raw(&self) -> &Self::Modulus;
}

impl CryptoModulus for LevelOne {
    type Modulus = U128;
    type OddModulus = Odd<U128>;
    type ConstMontyForm = ConstMontyFormQ1;
    const R: Self::OddModulus = Q1::MODULUS;

    fn monty_mul(&self, y: &Self) -> Self {
        let xx = Self::ConstMontyForm::new(&self.0);
        let yy = Self::ConstMontyForm::new(&y.0);
        Self((xx * yy).retrieve())
    }
    fn as_raw(&self) -> &U128 {
        &self.0
    }
}

impl CryptoModulus for LevelEll {
    type Modulus = U768;
    type OddModulus = Odd<U768>;
    type ConstMontyForm = ConstMontyFormQ;
    const R: Self::OddModulus = Q::MODULUS;

    fn monty_mul(&self, y: &Self) -> Self {
        let xx = Self::ConstMontyForm::new(&self.0);
        let yy = Self::ConstMontyForm::new(&y.0);
        Self((xx * yy).retrieve())
    }

    fn as_raw(&self) -> &U768 {
        &self.0
    }
}

impl CryptoModulus for LevelKsw {
    type Modulus = U1536;
    type OddModulus = Odd<U1536>;
    type ConstMontyForm = ConstMontyFormQR;
    const R: Self::OddModulus = QR::MODULUS;

    fn monty_mul(&self, y: &Self) -> Self {
        let xx = Self::ConstMontyForm::new(&self.0);
        let yy = Self::ConstMontyForm::new(&y.0);
        Self((xx * yy).retrieve())
    }

    fn as_raw(&self) -> &U1536 {
        &self.0
    }
}

/// Scaling factor is R from T = QR in the NIST document.
pub trait ScalingFactor {
    const FACTOR: Self;
}

impl ScalingFactor for GenericModulus<{ U1536::LIMBS }> {
    const FACTOR: Self = GenericModulus(U1536::from_be_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041004100001"));
}

impl ZConsts for LevelOne {
    const TWO: Self = GenericModulus(U128::from_u128(2));
    const THREE: Self = GenericModulus(U128::from_u128(3));
    /// MAX = Q1 - 1
    const MAX: Self = GenericModulus(U128::from_u128(4951835715005247202901360640));
}

impl ZConsts for LevelEll {
    const TWO: Self = GenericModulus(U768::from_u128(2));
    const THREE: Self = GenericModulus(U768::from_u128(3));
    const MAX: Self = GenericModulus(U768::from_be_hex("000000013355477e91f38705fa80df474d509fa966146c31d5f49736641be9317e77b16ec3619bd8ba71189114d10d908b63d80f63622d3b5be88e621c1f50977b47d27011bac33a104d116606db87cb392a4d10e672c7f1f8ce98198bf60000"));
}

impl ZConsts for LevelKsw {
    const TWO: Self = GenericModulus(U1536::from_u128(2));
    const THREE: Self = GenericModulus(U1536::from_u128(3));
    const MAX: Self = GenericModulus(U1536::from_be_hex("0000000000004cd59eb4f65c863e6061b6720b25fb3e816f749190899b4abed4935359ea4bf99d3417ce959274c08b588898663d18dccedc64276248fa92aaa05b2db2f7d36df90ab53d34e1c86cc61063a9b03d618ecce0eb993030243a0de47250bca4d2dabd1cc5c8443b23b396fea076dd16222feaced44ea1ab836e816c0cfa8e6d4f4ad4b1191cc50e75a511b208bf580c8549fc9009b234fe574b0ba66948f50b66b3aacc9aa096d5ec4cd84c801ec65ff4bf770477f7338990060000"));
}

impl LevelOne {
    // TODO(Dragos) can we remove the OK() since this is never going to fail?
    pub fn to_scalar(&self) -> anyhow::Result<u128> {
        Ok(u128::from(self.0))
    }
}

// Ring traits for generic modulus

impl Ring for LevelEll {
    const BIT_LENGTH: usize = unimplemented!();
    const CHAR_LOG2: usize = unimplemented!();

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Ring for LevelOne {
    const BIT_LENGTH: usize = unimplemented!();
    const CHAR_LOG2: usize = unimplemented!();

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Ring for LevelKsw {
    const BIT_LENGTH: usize = unimplemented!();
    const CHAR_LOG2: usize = unimplemented!();

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl<const LIMBS: usize> Serialize for GenericModulus<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, const LIMBS: usize> Deserialize<'de> for GenericModulus<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GenericModulus(Uint::<LIMBS>::deserialize(deserializer)?))
    }
}

impl<const LIMBS: usize> Neg for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(self.0.neg_mod(&Self::R))
    }
}

impl<const LIMBS: usize> Sample for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    fn sample<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        GenericModulus(<Self as CryptoModulus>::Modulus::random_mod(
            rng,
            <Self as CryptoModulus>::R.as_nz_ref(),
        ))
    }
}

impl<const LIMBS: usize> FromU128 for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    fn from_u128(value: u128) -> Self {
        GenericModulus(Uint::<LIMBS>::from_u128(value))
    }
}

impl<const LIMBS: usize> Sum for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    fn sum<I: Iterator<Item = GenericModulus<LIMBS>>>(iter: I) -> Self {
        let mut res = <Self as CryptoModulus>::Modulus::default();
        for items in iter {
            res = res.add_mod(&items.0, &Self::R)
        }
        Self(res)
    }
}

impl<const LIMBS: usize> MulAssign for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::monty_mul(self, &rhs);
    }
}

impl<const LIMBS: usize> Mul for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::monty_mul(&self, &rhs)
    }
}

impl<const LIMBS: usize> SubAssign for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.sub_mod(&rhs.0, &Self::R)
    }
}

impl<const LIMBS: usize> Sub for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    type Output = Self;
    fn sub(self, other: Self) -> Self::Output {
        Self(self.0.sub_mod(&other.0, &Self::R))
    }
}

impl<const LIMBS: usize> Add for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        Self(self.0.add_mod(&other.0, &Self::R))
    }
}

impl<const LIMBS: usize> One for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    const ONE: Self = Self(Uint::<LIMBS>::from_u128(1));
}

impl<const LIMBS: usize> Zero for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    const ZERO: Self = Self(Uint::<LIMBS>::from_u128(0));
}

impl<const LIMBS: usize> AddAssign for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.add_mod(&rhs.0, &Self::R)
    }
}

/// NTT Reqs:
///
impl<'r, const LIMBS: usize> Mul<&'r GenericModulus<LIMBS>> for GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    type Output = GenericModulus<LIMBS>;
    fn mul(self, rhs: &'r GenericModulus<LIMBS>) -> Self::Output {
        Self::monty_mul(&self, rhs)
    }
}

/// BGV reqs to avoid cloning
impl<'l, 'r, const LIMBS: usize> Sub<&'r GenericModulus<LIMBS>> for &'l GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    type Output = GenericModulus<LIMBS>;
    fn sub(self, other: &'r GenericModulus<LIMBS>) -> Self::Output {
        GenericModulus(self.0.sub_mod(&other.0, &GenericModulus::<LIMBS>::R))
    }
}

impl<'l, 'r, const LIMBS: usize> Mul<&'r GenericModulus<LIMBS>> for &'l GenericModulus<LIMBS>
where
    GenericModulus<LIMBS>: CryptoModulus<Modulus = Uint<LIMBS>, OddModulus = Odd<Uint<LIMBS>>>,
{
    type Output = GenericModulus<LIMBS>;
    fn mul(self, rhs: &'r GenericModulus<LIMBS>) -> Self::Output {
        GenericModulus::monty_mul(self, rhs)
    }
}

impl Div for LevelOne {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        // we always have an inverse here
        let inv = rhs.0.inv_odd_mod(&Self::R).unwrap();
        Self(self.0.mul_mod(&inv, &Self::R))
    }
}

impl DivAssign for LevelOne {
    fn div_assign(&mut self, rhs: Self) {
        // we always have an inverse here since we work in a field.
        let inv = rhs.0.inv_odd_mod(&Self::R).unwrap();
        self.0 = self.0.mul_mod(&inv, &Self::R);
    }
}

lazy_static! {
    static ref LAGRANGE_STORE_BGV: RwLock<HashMap<Vec<LevelOne>, Vec<Poly<LevelOne>>>> =
        RwLock::new(HashMap::new());
}

impl Field for LevelOne {
    fn memoize_lagrange(points: &[Self]) -> anyhow::Result<Vec<Poly<Self>>> {
        if let Ok(lock_lagrange_store) = LAGRANGE_STORE_BGV.read() {
            match lock_lagrange_store.get(points) {
                Some(v) => Ok(v.clone()),
                None => {
                    drop(lock_lagrange_store);
                    if let Ok(mut lock_lagrange_store) = LAGRANGE_STORE_BGV.write() {
                        let lagrange_pols = lagrange_polynomials(points);
                        lock_lagrange_store.insert(points.to_vec(), lagrange_pols.clone());
                        Ok(lagrange_pols)
                    } else {
                        Err(anyhow_error_and_log(
                            "Error writing LAGRANGE_STORE".to_string(),
                        ))
                    }
                }
            }
        } else {
            Err(anyhow_error_and_log(
                "Error reading LAGRANGE_STORE".to_string(),
            ))
        }
    }

    fn invert(&self) -> Self {
        let inv = self.0.inv_odd_mod(&Self::R).unwrap();
        Self(inv)
    }
}

impl RingEmbed for LevelOne {
    fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self> {
        Ok(Self::from_u128(idx as u128))
    }
}

impl ErrorCorrect for LevelOne {
    fn error_correct(
        sharing: &ShamirSharings<LevelOne>,
        threshold: usize,
        max_correctable_errs: usize,
    ) -> anyhow::Result<Poly<LevelOne>> {
        let shares: Vec<_> = sharing
            .shares
            .iter()
            .map(|share| ShamirSharing {
                share: share.value(),
                party_id: share.owner().one_based() as u8,
            })
            .collect();
        let res = error_correction(shares.as_slice(), threshold, max_correctable_errs)?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::algebra::poly::lagrange_interpolation;
    use crate::execution::sharing::shamir::{InputOp, RevealOp};
    use crate::execution::sharing::shamir::{ShamirFieldPoly, ShamirSharings};
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_l1_add() {
        let x = LevelOne::from_u128(1);
        let y = LevelOne::from_u128(4951835715005247202901360640);
        assert_eq!(x + y, LevelOne::ZERO);

        assert_eq!(LevelOne::from_u128(2) + y, LevelOne::ONE);
    }

    #[test]
    fn test_l1_mul() {
        let p_minus_1 = LevelOne::from_u128(4951835715005247202901360640);
        assert_eq!(
            LevelOne::from_u128(2) * p_minus_1,
            LevelOne::from_u128(4951835715005247202901360639)
        );
        assert_eq!(
            LevelOne::from_u128(123456789101112) * LevelOne::from_u128(123456789101112),
            LevelOne::from_u128(386071630140705100255554621)
        );
    }

    #[test]
    fn test_l1_poly_eval() {
        let poly = Poly {
            coefs: vec![LevelOne::from_u128(11), LevelOne::from_u128(1)],
        };
        let xs = [LevelOne::from_u128(0), LevelOne::from_u128(1)];
        let ys: Vec<_> = xs.iter().map(|x| poly.eval(x)).collect();
        assert_eq!(ys[0], LevelOne::from_u128(11));
        assert_eq!(ys[1], LevelOne::from_u128(12));
    }

    #[test]
    fn test_l1_division() {
        assert_eq!(
            LevelOne::from_u128(2) / LevelOne::from_u128(2),
            LevelOne::ONE
        );
        assert_eq!(
            LevelOne::from_u128(123456789) / LevelOne::from_u128(123456789),
            LevelOne::ONE
        );
    }

    #[test]
    fn test_l1_lagrange() {
        let poly = Poly {
            coefs: vec![
                LevelOne::from_u128(11),
                LevelOne::from_u128(2),
                LevelOne::from_u128(3),
                LevelOne::from_u128(22),
                LevelOne::from_u128(9),
            ],
        };
        let xs = vec![
            LevelOne::from_u128(0),
            LevelOne::from_u128(1),
            LevelOne::from_u128(2),
            LevelOne::from_u128(3),
            LevelOne::from_u128(4),
        ];

        // we need at least degree + 1 points to interpolate
        assert!(xs.len() > poly.deg());

        let ys: Vec<_> = xs.iter().map(|x| poly.eval(x)).collect();
        let interpolated = lagrange_interpolation(&xs, &ys);
        assert_eq!(poly, interpolated.unwrap());
    }

    #[test]
    fn test_field_reconstruct() {
        let f = ShamirFieldPoly::<LevelOne> {
            coefs: vec![
                LevelOne::from_u128(12345),
                LevelOne::from_u128(1234567),
                LevelOne::from_u128(12345678910),
            ],
        };

        let num_parties = 7;
        let threshold = f.coefs.len() - 1; // = 2 here
        let max_err = (num_parties as usize - threshold) / 2; // = 2 here

        let mut shares: Vec<_> = (1..=num_parties)
            .map(|x| ShamirSharing::<LevelOne> {
                share: f.eval(&LevelOne::from_u128(x as u128)),
                party_id: x,
            })
            .collect();

        // modify shares of parties 1 and 2
        shares[1].share += LevelOne::from_u128(10);
        shares[2].share += LevelOne::from_u128(254);

        let secret_poly = error_correction(&shares, threshold, max_err).unwrap();
        assert_eq!(secret_poly, f);
    }

    #[test]
    fn test_field_sharings() {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = LevelOne::from_u128(2345);
        let num_parties = 8;
        let threshold = 2;
        let max_err = 0;
        let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();
        let f_zero = sharing.err_reconstruct(threshold, max_err).unwrap();
        assert_eq!(f_zero.to_scalar().unwrap(), secret.to_scalar().unwrap());
    }
}
