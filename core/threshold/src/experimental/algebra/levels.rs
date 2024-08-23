use crate::algebra::gf256::error_correction;
use crate::algebra::poly::lagrange_polynomials;
use crate::algebra::poly::Poly;
use crate::algebra::structure_traits::ErrorCorrect;
use crate::algebra::structure_traits::FromU128;
use crate::algebra::structure_traits::Invert;
use crate::algebra::structure_traits::Ring;
use crate::algebra::structure_traits::RingEmbed;
use crate::algebra::structure_traits::ZConsts;
use crate::algebra::structure_traits::{Field, One, Sample, Zero};
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::sharing::shamir::ShamirSharing;
use crate::execution::sharing::shamir::ShamirSharings;
use crate::execution::sharing::share::Share;
use crate::execution::small_execution::prf::PRSSConversions;
use crypto_bigint::impl_modulus;
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::Limb;
use crypto_bigint::NonZero;
use crypto_bigint::Odd;
use crypto_bigint::RandomMod;
use crypto_bigint::Uint;
use crypto_bigint::U1536;
use crypto_bigint::{U128, U64, U768};
use itertools::Itertools;
use lazy_static::lazy_static;
use rand::CryptoRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::sync::RwLock;

use crate::experimental::algebra::crt::from_crt;
use crate::experimental::algebra::crt::to_crt;
use crate::experimental::algebra::crt::LevelKswCrtRepresentation;
use crate::experimental::gen_bits_odd::LargestPrimeFactor;

/// Basic moduli trait for data mod Q, to avoid code duplication.
pub trait CryptoModulus {
    /// This makes easy to grab the underlying crypto_bigint type
    type Modulus;
    /// This makes it easy to grab the Odd<_> version of the underlying crypto_bigint type.
    type OddModulus;
    /// Type used for accessing custom montgomery multiplication from bigint library.
    type ConstMontyForm;
    /// The modulus in which operations are performed, retrieved from the impl_modulus macro.
    const MODULUS: Self::OddModulus;
    /// Perform montgomery multiplication modulo R.
    fn monty_mul(&self, y: &Self) -> Self;
    /// Retrieve reference from inner bigint type.
    fn as_raw(&self) -> &Self::Modulus;
}

#[derive(Hash, Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct GenericModulus<const LIMBS: usize>(pub Uint<LIMBS>);

pub type ModulusSize64 = GenericModulus<{ U64::LIMBS }>;
pub type ModulusSize128 = GenericModulus<{ U128::LIMBS }>;
pub type ModulusSize768 = GenericModulus<{ U768::LIMBS }>;
pub type ModulusSize1536 = GenericModulus<{ U1536::LIMBS }>;

macro_rules! impl_ring_level {
    ($name:ident, $uint_type:ty, $modulus_size_type: ty, $q_type: ty, $monty_form: ty, $max_val: expr) => {
        paste::item! {
            #[derive(Hash, Debug, Default, Clone, Copy, Eq, PartialEq)]
            pub struct $name {
                pub value: $modulus_size_type,
            }

            impl CryptoModulus for $name {
                type Modulus = $uint_type;
                type OddModulus = Odd<$uint_type>;
                type ConstMontyForm = $monty_form;
                const MODULUS: Self::OddModulus = <$q_type>::MODULUS;

                fn monty_mul(&self, y: &Self) -> Self {
                    let xx = Self::ConstMontyForm::new(&self.value.0);
                    let yy = Self::ConstMontyForm::new(&y.value.0);
                    Self {
                        value: GenericModulus((xx * yy).retrieve()),
                    }
                }
                fn as_raw(&self) -> &$uint_type {
                    &self.value.0
                }
            }

            impl ZConsts for $name {
                const TWO: Self = Self {
                    value: GenericModulus(<$uint_type>::from_u128(2)),
                };
                const THREE: Self = Self {
                    value: GenericModulus(<$uint_type>::from_u128(3)),
                };
                /// MAX = Q1 - 1
                const MAX: Self = Self {
                    value: GenericModulus($uint_type::from_be_hex($max_val)),
                };
            }

            impl Ring for $name {
                ///BIT LENGTH FOR THIS RING IS DEFINED AS THE NUMBER OF BITS REQUIRED TO SAMPLE
                ///AN ELEMENT FROM A DISTRIBUTION INDISTINGUISHABLE FROM THE UNIFORM DISTRIBUTION
                const BIT_LENGTH: usize = $uint_type::from_be_hex($max_val).bits() as usize ;
                const NUM_BITS_STAT_SEC_BASE_RING: usize = Self::BIT_LENGTH + (crate::execution::constants::STATSEC as usize);
                const CHAR_LOG2: usize = unimplemented!();
                const EXTENSION_DEGREE: usize = 1;

                fn to_byte_vec(&self) -> Vec<u8> {
                    self.value.0.to_le_bytes().to_vec()
                }
            }

            impl Neg for $name {
                type Output = Self;

                fn neg(self) -> Self::Output {
                    let value = self.value.0.neg_mod(&Self::MODULUS);
                    Self {
                        value: GenericModulus(value),
                    }
                }
            }

            impl Zero for $name {
                const ZERO: Self = Self {
                    value: GenericModulus(<$uint_type>::from_u8(0)),
                };
            }

            impl One for $name {
                const ONE: Self = Self {
                    value: GenericModulus(<$uint_type>::from_u8(1)),
                };
            }

            impl Add<$name> for $name {
                type Output = Self;

                fn add(self, rhs: $name) -> Self::Output {
                    Self {
                        value: GenericModulus(self.value.0.add_mod(&rhs.value.0, &Self::MODULUS)),
                    }
                }
            }

            impl AddAssign<$name> for $name {
                fn add_assign(&mut self, rhs: $name) {
                    let res = *self + rhs;
                    self.value = res.value;
                }
            }

            impl Sum for $name {
                fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                    let mut res = Self::ZERO;
                    for elem in iter {
                        res += elem;
                    }
                    res
                }
            }

            impl Sub<$name> for $name {
                type Output = Self;

                fn sub(self, rhs: $name) -> Self::Output {
                    Self {
                        value: GenericModulus(self.value.0.sub_mod(&rhs.value.0, &Self::MODULUS)),
                    }
                }
            }

            impl SubAssign<$name> for $name {
                fn sub_assign(&mut self, rhs: $name) {
                    let res = *self - rhs;
                    self.value = res.value;
                }
            }

            impl<'l, 'r> Sub<&'r $name> for &'l $name {
                type Output = $name;

                fn sub(self, rhs: &'r $name) -> Self::Output {
                    $name {
                        value: GenericModulus(self.value.0.sub_mod(&rhs.value.0, & $name::MODULUS)),
                    }
                }
            }

            impl Mul<$name> for $name {
                type Output = Self;

                fn mul(self, rhs: $name) -> Self::Output {
                    Self::monty_mul(&self, &rhs)
                }
            }

            impl<'r> Mul<&'r $name> for $name {
                type Output = $name;
                fn mul(self, rhs: &'r $name) -> Self::Output {
                    Self::monty_mul(&self, rhs)
                }
            }

            impl<'l, 'r> Mul<&'r $name> for &'l $name {
                type Output = $name;

                fn mul(self, rhs: &'r $name) -> Self::Output {
                    $name::monty_mul(self, rhs)
                }
            }

            impl MulAssign<$name> for $name {
                fn mul_assign(&mut self, rhs: $name) {
                    let res = *self * rhs;
                    self.value = res.value;
                }
            }

            impl Sample for $name {
                fn sample<R: Rng + CryptoRng>(rng: &mut R) -> Self {
                    Self {
                        value: GenericModulus(<Self as CryptoModulus>::Modulus::random_mod(
                            rng,
                            Self::MODULUS.as_nz_ref(),
                        )),
                    }
                }
            }

            impl Serialize for $name {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    self.value.0.serialize(serializer)
                }
            }

            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    Ok(Self {
                        value: GenericModulus(<$uint_type>::deserialize(deserializer)?),
                    })
                }
            }
        }
    };
}

macro_rules! impl_from_u128_small {
    ($name:ident) => {
        impl FromU128 for $name {
            //WARNING: WILL PANIC FOR THE SMALL LEVELS
            fn from_u128(value: u128) -> Self {
                let value = GenericModulus(
                    U128::from_u128(value)
                        .split()
                        .0
                        .rem(Self::MODULUS.as_nz_ref()),
                );
                return Self { value };
            }
        }
    };
}

macro_rules! impl_from_u128_big {
    ($name:ident, $uint_type:ty) => {
        impl FromU128 for $name {
            //WARNING: WILL PANIC FOR THE SMALL LEVELS
            fn from_u128(value: u128) -> Self {
                let value =
                    GenericModulus(<$uint_type>::from_u128(value).rem(Self::MODULUS.as_nz_ref()));
                return Self { value };
            }
        }
    };
}

macro_rules! impl_field_level {
    ($name:ident, $uint_type:ty, $modulus_size_type: ty, $q_type: ty, $monty_form: ty, $max_val: expr) => {
        paste::item!{
            impl_ring_level!($name, $uint_type, $modulus_size_type, $q_type, $monty_form, $max_val);
            impl Div for $name {
                type Output = Self;
                #[allow(clippy::suspicious_arithmetic_impl)]
                fn div(self, rhs: Self) -> Self::Output {
                    // we always have an inverse here
                    let inv = Self {
                        value: GenericModulus(rhs.value.0.inv_odd_mod(&Self::MODULUS).unwrap()),
                    };
                    self * inv
                }
            }

            impl DivAssign for $name {
                fn div_assign(&mut self, rhs: Self) {
                    // we always have an inverse here since we work in a field.
                    let res = *self / rhs;
                    self.value = res.value;
                }
            }

            lazy_static! {
                static ref [<LAGRANGE_STORE_BGV_ $name:upper>]: RwLock<HashMap<Vec<$name>, Vec<Poly<$name>>>> =
                    RwLock::new(HashMap::new());
            }

            impl Field for $name {
                fn memoize_lagrange(points: &[Self]) -> anyhow::Result<Vec<Poly<Self>>> {
                    if let Ok(lock_lagrange_store) = [<LAGRANGE_STORE_BGV_ $name:upper>].read() {
                        match lock_lagrange_store.get(points) {
                            Some(v) => Ok(v.clone()),
                            None => {
                                drop(lock_lagrange_store);
                                if let Ok(mut lock_lagrange_store) = [<LAGRANGE_STORE_BGV_ $name:upper>].write() {
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
                    Self::ONE / *self
                }
            }

            impl RingEmbed for $name {
                fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self> {
                    Ok(Self::from_u128(idx as u128))
                }
            }

            impl ErrorCorrect for $name {
                fn error_correct(
                    sharing: &ShamirSharings<$name>,
                    threshold: usize,
                    max_errs: usize,
                ) -> anyhow::Result<Poly<$name>> {
                    let shares: Vec<_> = sharing
                        .shares
                        .iter()
                        .map(|share| ShamirSharing {
                            share: share.value(),
                            party_id: share.owner().one_based() as u8,
                        })
                        .collect();
                    let res = error_correction(shares.as_slice(), threshold, max_errs)?;

                    Ok(res)
                }
            }
            }
    };
}

impl RingEmbed for LevelKsw {
    fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self> {
        Ok(Self::from_u128(idx as u128))
    }
}

impl ErrorCorrect for LevelKsw {
    fn error_correct(
        sharing: &ShamirSharings<Self>,
        threshold: usize,
        max_errs: usize,
    ) -> anyhow::Result<Poly<Self>> {
        //Apply CRT decomposition to all the shares
        let crt_shares = sharing
            .shares
            .iter()
            .map(|share| (to_crt(share.value()), share.owner()))
            .collect_vec();

        let shamir_level_r = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_r))
                .collect_vec(),
        };
        let mut res_level_r = LevelR::error_correct(&shamir_level_r, threshold, max_errs)?;

        let shamir_level_one = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_one))
                .collect_vec(),
        };
        let mut res_level_one = LevelOne::error_correct(&shamir_level_one, threshold, max_errs)?;

        let shamir_level_two = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_two))
                .collect_vec(),
        };
        let mut res_level_two = LevelTwo::error_correct(&shamir_level_two, threshold, max_errs)?;

        let shamir_level_three = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_three))
                .collect_vec(),
        };
        let mut res_level_three =
            LevelThree::error_correct(&shamir_level_three, threshold, max_errs)?;

        let shamir_level_four = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_four))
                .collect_vec(),
        };
        let mut res_level_four = LevelFour::error_correct(&shamir_level_four, threshold, max_errs)?;

        let shamir_level_five = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_five))
                .collect_vec(),
        };
        let mut res_level_five = LevelFive::error_correct(&shamir_level_five, threshold, max_errs)?;

        let shamir_level_six = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_six))
                .collect_vec(),
        };
        let mut res_level_six = LevelSix::error_correct(&shamir_level_six, threshold, max_errs)?;

        let shamir_level_seven = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_seven))
                .collect_vec(),
        };
        let mut res_level_seven =
            LevelSeven::error_correct(&shamir_level_seven, threshold, max_errs)?;

        let shamir_level_eight = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_eight))
                .collect_vec(),
        };
        let mut res_level_eight =
            LevelEight::error_correct(&shamir_level_eight, threshold, max_errs)?;

        let shamir_level_nine = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_nine))
                .collect_vec(),
        };
        let mut res_level_nine = LevelNine::error_correct(&shamir_level_nine, threshold, max_errs)?;

        let shamir_level_ten = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_ten))
                .collect_vec(),
        };
        let mut res_level_ten = LevelTen::error_correct(&shamir_level_ten, threshold, max_errs)?;

        let shamir_level_eleven = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_eleven))
                .collect_vec(),
        };
        let mut res_level_eleven =
            LevelEleven::error_correct(&shamir_level_eleven, threshold, max_errs)?;

        let shamir_level_twelve = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_twelve))
                .collect_vec(),
        };
        let mut res_level_twelve =
            LevelTwelve::error_correct(&shamir_level_twelve, threshold, max_errs)?;

        let shamir_level_thirteen = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_thirteen))
                .collect_vec(),
        };
        let mut res_level_thirteen =
            LevelThirteen::error_correct(&shamir_level_thirteen, threshold, max_errs)?;

        let shamir_level_fourteen = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_fourteen))
                .collect_vec(),
        };
        let mut res_level_fourteen =
            LevelFourteen::error_correct(&shamir_level_fourteen, threshold, max_errs)?;

        let shamir_level_fifteen = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_fifteen))
                .collect_vec(),
        };
        let mut res_level_fifteen =
            LevelFifteen::error_correct(&shamir_level_fifteen, threshold, max_errs)?;

        //All the level polynomial have max degree threshold, so we will crt reconstruct a polynomial of degree threshold
        let mut coefs: Vec<Self> = Vec::new();
        //Doing stuff in reverse order to get ownership with remove,
        //without having to pay for worst case complexity of moving all elements of the vector at every iteration
        for monomial_index in (0..=threshold).rev() {
            let value_level_one = if res_level_one.coefs.len() - 1 == monomial_index {
                res_level_one.coefs.remove(monomial_index)
            } else {
                LevelOne::ZERO
            };

            let value_level_two = if res_level_two.coefs.len() - 1 == monomial_index {
                res_level_two.coefs.remove(monomial_index)
            } else {
                LevelTwo::ZERO
            };

            let value_level_three = if res_level_three.coefs.len() - 1 == monomial_index {
                res_level_three.coefs.remove(monomial_index)
            } else {
                LevelThree::ZERO
            };

            let value_level_four = if res_level_four.coefs.len() - 1 == monomial_index {
                res_level_four.coefs.remove(monomial_index)
            } else {
                LevelFour::ZERO
            };

            let value_level_five = if res_level_five.coefs.len() - 1 == monomial_index {
                res_level_five.coefs.remove(monomial_index)
            } else {
                LevelFive::ZERO
            };

            let value_level_six = if res_level_six.coefs.len() - 1 == monomial_index {
                res_level_six.coefs.remove(monomial_index)
            } else {
                LevelSix::ZERO
            };

            let value_level_seven = if res_level_seven.coefs.len() - 1 == monomial_index {
                res_level_seven.coefs.remove(monomial_index)
            } else {
                LevelSeven::ZERO
            };

            let value_level_eight = if res_level_eight.coefs.len() - 1 == monomial_index {
                res_level_eight.coefs.remove(monomial_index)
            } else {
                LevelEight::ZERO
            };

            let value_level_nine = if res_level_nine.coefs.len() - 1 == monomial_index {
                res_level_nine.coefs.remove(monomial_index)
            } else {
                LevelNine::ZERO
            };

            let value_level_ten = if res_level_ten.coefs.len() - 1 == monomial_index {
                res_level_ten.coefs.remove(monomial_index)
            } else {
                LevelTen::ZERO
            };

            let value_level_eleven = if res_level_eleven.coefs.len() - 1 == monomial_index {
                res_level_eleven.coefs.remove(monomial_index)
            } else {
                LevelEleven::ZERO
            };

            let value_level_twelve = if res_level_twelve.coefs.len() - 1 == monomial_index {
                res_level_twelve.coefs.remove(monomial_index)
            } else {
                LevelTwelve::ZERO
            };

            let value_level_thirteen = if res_level_thirteen.coefs.len() - 1 == monomial_index {
                res_level_thirteen.coefs.remove(monomial_index)
            } else {
                LevelThirteen::ZERO
            };

            let value_level_fourteen = if res_level_fourteen.coefs.len() - 1 == monomial_index {
                res_level_fourteen.coefs.remove(monomial_index)
            } else {
                LevelFourteen::ZERO
            };

            let value_level_fifteen = if res_level_fifteen.coefs.len() - 1 == monomial_index {
                res_level_fifteen.coefs.remove(monomial_index)
            } else {
                LevelFifteen::ZERO
            };

            let value_level_r = if res_level_r.coefs.len() - 1 == monomial_index {
                res_level_r.coefs.remove(monomial_index)
            } else {
                LevelR::ZERO
            };

            coefs.push(from_crt(LevelKswCrtRepresentation {
                value_level_one,
                value_level_two,
                value_level_three,
                value_level_four,
                value_level_five,
                value_level_six,
                value_level_seven,
                value_level_eight,
                value_level_nine,
                value_level_ten,
                value_level_eleven,
                value_level_twelve,
                value_level_thirteen,
                value_level_fourteen,
                value_level_fifteen,
                value_level_r,
            }))
        }
        coefs.reverse();
        Ok(Poly { coefs })
    }
}

impl PRSSConversions for LevelKsw {
    //Because of the additional STAT SEC bits, need to temporarily switch to bigger uint
    fn from_u128_chunks(coefs: Vec<u128>) -> Self {
        assert!(coefs.len() * 128 > Self::BIT_LENGTH);
        let mut bytes = coefs
            .iter()
            .map(|coef| coef.to_le_bytes().to_vec())
            .collect_vec()
            .into_iter()
            .flatten()
            .collect_vec();

        let expected_size = crypto_bigint::U1600::LIMBS * Limb::BYTES;
        bytes.resize(expected_size, 0);
        let modulus_1600: crypto_bigint::U1600 = Self::MODULUS.as_ref().into();
        let value =
            crypto_bigint::U1600::from_le_slice(&bytes).rem(&NonZero::new(modulus_1600).unwrap());

        Self {
            value: GenericModulus((&value).into()),
        }
    }

    fn from_i128(value: i128) -> Self {
        let res = Self {
            value: GenericModulus(
                U1536::from_u128(value.unsigned_abs()).rem(Self::MODULUS.as_nz_ref()),
            ),
        };
        if value < 0 {
            res.neg()
        } else {
            res
        }
    }
}

impl Invert for LevelKsw {
    fn invert(self) -> anyhow::Result<Self> {
        let inverse = self.value.0.inv_odd_mod(&Self::MODULUS);
        if inverse.is_none().into() {
            Err(anyhow_error_and_log(format!("Could not invert {:?}", self)))
        } else {
            Ok(Self {
                value: GenericModulus(inverse.unwrap()),
            })
        }
    }
}

impl LevelR {
    fn pow(&self, exp: Self) -> Self {
        let mut res = Self::ONE;
        let mut x = *self;
        let mut exp = exp;

        while exp != Self::ZERO {
            //If odd, multiply x to result
            if exp.value.0.bit_vartime(0) {
                res *= x;
            }
            exp.value.0 = exp.value.0.shr_vartime(1);
            x *= x;
        }
        res
    }
}

impl LargestPrimeFactor for LevelKsw {
    fn mod_largest_prime(v: &Self) -> Self {
        let modulus_r: U1536 = LevelR::MODULUS.as_ref().into();
        Self {
            value: GenericModulus(v.value.0.rem(&NonZero::new(modulus_r).unwrap())),
        }
    }

    fn largest_prime_factor_non_zero(v: &Self) -> bool {
        let v_mod_largest_prime = Self::mod_largest_prime(v);
        v_mod_largest_prime != Self::ZERO
    }

    /// Projects a [`LevelKsw`] value onto the field defined by its largest prime factor [`LevelR::MODULUS`],
    /// and computes its square root.
    ///
    ///
    /// Uses the Tonelli-Shanks algorithm, which requires:
    /// - factoring [`LevelR::MODULUS`] - 1 as 2^S * Q with Q odd
    /// - finding a quadratic non-residue in the field defined by [`LevelR::MODULUS`]
    ///
    /// We can thus precomputes some values that are defined as constants:
    /// - ODD_DIV: corresponds to the Q in the factorisation above
    /// - ODD_DIV_PLUS_ONE_DIV_TWO: corresponds to (Q+1)/2
    /// - POW_2: corresponds to the S in the factorisation above
    /// - QUADRATIC_NON_RESIDUE_TO_ODD_DIV: corresponds to the quadratic non-residue above to the power Q
    fn largest_prime_factor_sqrt(v: &Self) -> Self {
        const ODD_DIV : LevelR = LevelR { value : GenericModulus(U768::from_be_hex("000000020002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001")) };

        const ODD_DIV_PLUS_ONE_DIV_TWO : LevelR = LevelR { value : GenericModulus(U768::from_be_hex("000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008001")) };

        const QUADRATIC_NON_RESIDUE_TO_ODD_DIV: LevelR = LevelR { value : GenericModulus(U768::from_be_hex("0014b7fee458dd7dd4e6ce7bce017db91e1bb0121d4d68efcce15f599f335bc0050cb567c13241e1b55e68a20fdc18a3eb9d578a2f887f3f5333504df8080474ee8e4224fcf3f1e367978651e086063d310aa6233b6ff38386484eade8340227")) };

        const POW_2: u128 = 20_u128;

        let modulus_r: U1536 = LevelR::MODULUS.as_ref().into();
        let value_level_r = LevelR {
            value: GenericModulus((&v.value.0.rem(&NonZero::new(modulus_r).unwrap())).into()),
        };

        let mut m = POW_2;
        let mut c = QUADRATIC_NON_RESIDUE_TO_ODD_DIV;
        let mut t = value_level_r.pow(ODD_DIV);
        let mut r = value_level_r.pow(ODD_DIV_PLUS_ONE_DIV_TWO);
        while t != LevelR::ONE {
            let i = {
                let mut i = 1;
                while t.pow(LevelR::from_u128(1 << i)) != LevelR::ONE {
                    i += 1;
                }
                assert!(i < m);
                i
            };

            let b = c.pow(LevelR::from_u128(1 << (m - i - 1)));
            c = b * b;
            t *= c;
            r *= b;
            m = i;
            assert!(t != LevelR::ZERO);
        }

        Self {
            value: GenericModulus((&r.value.0).into()),
        }
    }
}

impl Invert for LevelOne {
    fn invert(self) -> anyhow::Result<Self> {
        Ok(Self::ONE / self)
    }
}

impl PRSSConversions for LevelOne {
    //Because of the additional STAT SEC bits, need to temporarily switch to bigger uint
    fn from_u128_chunks(coefs: Vec<u128>) -> Self {
        assert!(coefs.len() * 128 > Self::BIT_LENGTH);
        let mut bytes = coefs
            .iter()
            .map(|coef| coef.to_le_bytes().to_vec())
            .collect_vec()
            .into_iter()
            .flatten()
            .collect_vec();
        let expected_size = crypto_bigint::U192::LIMBS * Limb::BYTES;
        bytes.resize(expected_size, 0);
        let modulus_192: crypto_bigint::U192 = Self::MODULUS.as_ref().into();
        let value =
            crypto_bigint::U192::from_le_slice(&bytes).rem(&NonZero::new(modulus_192).unwrap());

        Self {
            value: GenericModulus((&value).into()),
        }
    }

    fn from_i128(value: i128) -> Self {
        let res = Self {
            value: GenericModulus(
                U128::from_u128(value.unsigned_abs()).rem(Self::MODULUS.as_nz_ref()),
            ),
        };
        if value < 0 {
            res.neg()
        } else {
            res
        }
    }
}

// These are the moduli used in BGV/BGV: Q1, ..., Q_ell, Q, R, QR.
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

//Represents the Ring for the top level ciphertext (Q = Prod(Q_i))
impl_modulus!(Q, U768, "0001222af914e4316f14f3122c24aacc809463ded88ce9666b82273465fe9684403909b5fd2bad0d44657066389ebc255d8b3f308d3c5c994fec727e636d7f90195d9717a252c3df170b78982b201c0cdef18f4c51448d258e22b771102e0001");
type ConstMontyFormQ = crypto_bigint::modular::ConstMontyForm<Q, { U768::LIMBS }>;
impl_from_u128_big!(LevelEll, U768);
impl_ring_level!(LevelEll, U768, ModulusSize768, Q, ConstMontyFormQ, "0001222af914e4316f14f3122c24aacc809463ded88ce9666b82273465fe9684403909b5fd2bad0d44657066389ebc255d8b3f308d3c5c994fec727e636d7f90195d9717a252c3df170b78982b201c0cdef18f4c51448d258e22b771102e0000");

impl_modulus!(QR, U1536, "00000024458367fba8ca68cc44e3e6dade256c1c8e678d783e6a9d1256d1a65f905ad7a93de0dc35471e2e569975209e9883361397798d9d3ab590b84d5abd7c5fb31db60ea72d4cc63b5d51f4747708e59f5fcdc7bc121bcd436908b28b16a3b9def6b02d7b06a362826224e232f20047508314271614cf3eb1ef61d1d33574ae53ad451456f9c7d4b4bca7d3a887e22459dc8b55988346aeaaa257f24886e3b003fa3550fbbe19528feb67db06ffeae7ff75ee05c8e6620813ba61103e0001");
type ConstMontyFormQR = crypto_bigint::modular::ConstMontyForm<QR, { U1536::LIMBS }>;
impl_from_u128_big!(LevelKsw, U1536);
impl_ring_level!(LevelKsw, U1536, ModulusSize1536, QR, ConstMontyFormQR, "00000024458367fba8ca68cc44e3e6dade256c1c8e678d783e6a9d1256d1a65f905ad7a93de0dc35471e2e569975209e9883361397798d9d3ab590b84d5abd7c5fb31db60ea72d4cc63b5d51f4747708e59f5fcdc7bc121bcd436908b28b16a3b9def6b02d7b06a362826224e232f20047508314271614cf3eb1ef61d1d33574ae53ad451456f9c7d4b4bca7d3a887e22459dc8b55988346aeaaa257f24886e3b003fa3550fbbe19528feb67db06ffeae7ff75ee05c8e6620813ba61103e0000");

impl_modulus!(Q1, U128, "00000000400040000000001400140001");
type ConstMontyFormQ1 = crypto_bigint::modular::ConstMontyForm<Q1, { U128::LIMBS }>;
impl_from_u128_big!(LevelOne, U128);
impl_field_level!(
    LevelOne,
    U128,
    ModulusSize128,
    Q1,
    ConstMontyFormQ1,
    "00000000400040000000001400140000"
);

impl_modulus!(Q2, U64, "0000802880280001");
type ConstMontyFormQ2 = crypto_bigint::modular::ConstMontyForm<Q2, { U64::LIMBS }>;
impl_from_u128_small!(LevelTwo);
impl_field_level!(
    LevelTwo,
    U64,
    ModulusSize64,
    Q2,
    ConstMontyFormQ2,
    "0000802880280000"
);

impl_modulus!(Q3, U64, "0000802e802e0001");
type ConstMontyFormQ3 = crypto_bigint::modular::ConstMontyForm<Q3, { U64::LIMBS }>;
impl_from_u128_small!(LevelThree);
impl_field_level!(
    LevelThree,
    U64,
    ModulusSize64,
    Q3,
    ConstMontyFormQ3,
    "0000802e802e0000"
);

impl_modulus!(Q4, U64, "0000806080600001");
type ConstMontyFormQ4 = crypto_bigint::modular::ConstMontyForm<Q4, { U64::LIMBS }>;
impl_from_u128_small!(LevelFour);
impl_field_level!(
    LevelFour,
    U64,
    ModulusSize64,
    Q4,
    ConstMontyFormQ4,
    "0000806080600000"
);

impl_modulus!(Q5, U64, "000080b280b20001");
type ConstMontyFormQ5 = crypto_bigint::modular::ConstMontyForm<Q5, { U64::LIMBS }>;
impl_from_u128_small!(LevelFive);
impl_field_level!(
    LevelFive,
    U64,
    ModulusSize64,
    Q5,
    ConstMontyFormQ5,
    "000080b280b20000"
);

impl_modulus!(Q6, U64, "000080ca80ca0001");
type ConstMontyFormQ6 = crypto_bigint::modular::ConstMontyForm<Q6, { U64::LIMBS }>;
impl_from_u128_small!(LevelSix);
impl_field_level!(
    LevelSix,
    U64,
    ModulusSize64,
    Q6,
    ConstMontyFormQ6,
    "000080ca80ca0000"
);

impl_modulus!(Q7, U64, "000080d080d00001");
type ConstMontyFormQ7 = crypto_bigint::modular::ConstMontyForm<Q7, { U64::LIMBS }>;
impl_from_u128_small!(LevelSeven);
impl_field_level!(
    LevelSeven,
    U64,
    ModulusSize64,
    Q7,
    ConstMontyFormQ7,
    "000080d080d00000"
);

impl_modulus!(Q8, U64, "0000811e811e0001");
type ConstMontyFormQ8 = crypto_bigint::modular::ConstMontyForm<Q8, { U64::LIMBS }>;
impl_from_u128_small!(LevelEight);
impl_field_level!(
    LevelEight,
    U64,
    ModulusSize64,
    Q8,
    ConstMontyFormQ8,
    "0000811e811e0000"
);

impl_modulus!(Q9, U64, "0000813281320001");
type ConstMontyFormQ9 = crypto_bigint::modular::ConstMontyForm<Q9, { U64::LIMBS }>;
impl_from_u128_small!(LevelNine);
impl_field_level!(
    LevelNine,
    U64,
    ModulusSize64,
    Q9,
    ConstMontyFormQ9,
    "0000813281320000"
);

impl_modulus!(Q10, U64, "0000815a815a0001");
type ConstMontyFormQ10 = crypto_bigint::modular::ConstMontyForm<Q10, { U64::LIMBS }>;
impl_from_u128_small!(LevelTen);
impl_field_level!(
    LevelTen,
    U64,
    ModulusSize64,
    Q10,
    ConstMontyFormQ10,
    "0000815a815a0000"
);

impl_modulus!(Q11, U64, "0000819881980001");
type ConstMontyFormQ11 = crypto_bigint::modular::ConstMontyForm<Q11, { U64::LIMBS }>;
impl_from_u128_small!(LevelEleven);
impl_field_level!(
    LevelEleven,
    U64,
    ModulusSize64,
    Q11,
    ConstMontyFormQ11,
    "0000819881980000"
);

impl_modulus!(Q12, U64, "000081ae81ae0001");
type ConstMontyFormQ12 = crypto_bigint::modular::ConstMontyForm<Q12, { U64::LIMBS }>;
impl_from_u128_small!(LevelTwelve);
impl_field_level!(
    LevelTwelve,
    U64,
    ModulusSize64,
    Q12,
    ConstMontyFormQ12,
    "000081ae81ae0000"
);

impl_modulus!(Q13, U64, "000081fc81fc0001");
type ConstMontyFormQ13 = crypto_bigint::modular::ConstMontyForm<Q13, { U64::LIMBS }>;
impl_from_u128_small!(LevelThirteen);
impl_field_level!(
    LevelThirteen,
    U64,
    ModulusSize64,
    Q13,
    ConstMontyFormQ13,
    "000081fc81fc0000"
);

impl_modulus!(Q14, U64, "0000821082100001");
type ConstMontyFormQ14 = crypto_bigint::modular::ConstMontyForm<Q14, { U64::LIMBS }>;
impl_from_u128_small!(LevelFourteen);
impl_field_level!(
    LevelFourteen,
    U64,
    ModulusSize64,
    Q14,
    ConstMontyFormQ14,
    "0000821082100000"
);

impl_modulus!(Q15, U64, "0000821c821c0001");
type ConstMontyFormQ15 = crypto_bigint::modular::ConstMontyForm<Q15, { U64::LIMBS }>;
impl_from_u128_small!(LevelFifteen);
impl_field_level!(
    LevelFifteen,
    U64,
    ModulusSize64,
    Q15,
    ConstMontyFormQ15,
    "0000821c821c0000"
);

impl_modulus!(R, U768, "002000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000100001");
type ConstMontyFormR = crypto_bigint::modular::ConstMontyForm<R, { U768::LIMBS }>;
impl_from_u128_big!(LevelR, U768);
impl_field_level!(LevelR, U768, ModulusSize768, R, ConstMontyFormR, "002000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000100000");

/// Scaling factor is R from T = QR in the NIST document, but using the same underlying type as QR.
pub trait ScalingFactor {
    const FACTOR: Self;
}

impl ScalingFactor for LevelKsw {
    const FACTOR: Self = Self{value : GenericModulus(U1536::from_be_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000100000"))};
}

#[cfg(test)]
mod tests {
    use crate::algebra::poly::lagrange_interpolation;
    use crate::execution::config::BatchParams;
    use crate::execution::online::preprocessing::{RandomPreprocessing, TriplePreprocessing};
    use crate::execution::runtime::session::SmallSession;
    use crate::execution::sharing::shamir::{InputOp, RevealOp};
    use crate::execution::sharing::shamir::{ShamirFieldPoly, ShamirSharings};
    use crate::execution::small_execution::agree_random::RealAgreeRandom;
    use crate::execution::small_execution::offline::SmallPreprocessing;
    use crate::networking::NetworkMode;
    use crate::tests::helper::tests_and_benches::execute_protocol_small;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_l1_add() {
        let x = LevelOne::from_u128(1);
        let y = LevelOne::from_u128(19807342860020988141580320768);

        assert_eq!(x + y, LevelOne::ZERO);
        assert_eq!(LevelOne::from_u128(2) + y, LevelOne::ONE);
    }

    #[test]
    fn test_l1_mult() {
        let p_minus_1 = LevelOne::from_u128(19807342860020988141580320768);
        assert_eq!(
            LevelOne::from_u128(2) * p_minus_1,
            LevelOne::from_u128(19807342860020988141580320767)
        );

        assert_eq!(
            LevelOne::from_u128(123456789101112) * LevelOne::from_u128(123456789101112),
            LevelOne::from_u128(15241578775156446708959636544)
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
        assert_eq!(f_zero, secret);
    }

    #[test]
    fn test_crt_sharing() {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = LevelKsw::sample(&mut rng);
        let num_parties = 8;
        let threshold = 2;
        let max_err = 0;
        let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();
        let f_zero = sharing.err_reconstruct(threshold, max_err).unwrap();
        assert_eq!(f_zero, secret);
    }

    #[test]
    fn test_crt_sharing_w_error() {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = LevelKsw::sample(&mut rng);
        let num_parties = 8;
        let threshold = 2;
        let mut sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();
        sharing.shares[0] = Share::new(sharing.shares[0].owner(), LevelKsw::sample(&mut rng));
        sharing.shares[3] = Share::new(sharing.shares[3].owner(), LevelKsw::sample(&mut rng));
        let f_zero = sharing.err_reconstruct(threshold, threshold).unwrap();
        assert_eq!(f_zero, secret);
    }

    #[test]
    fn test_levelksw_triple_gen() {
        let parties = 5;
        let threshold = 1;
        let mut task = |mut session: SmallSession<LevelKsw>| async move {
            let batch_size = BatchParams {
                triples: 100,
                randoms: 100,
            };

            let mut prep =
                SmallPreprocessing::<LevelKsw, RealAgreeRandom>::init(&mut session, batch_size)
                    .await
                    .unwrap();
            (
                prep.next_triple_vec(100).unwrap(),
                prep.next_random_vec(100).unwrap(),
            )
        };
        //This is Sync because we are generating triples
        let results =
            execute_protocol_small(parties, threshold, None, NetworkMode::Sync, None, &mut task);

        //Reconstruct everything and check triples are triples
        for idx in 0..100 {
            let mut vec_x = Vec::new();
            let mut vec_y = Vec::new();
            let mut vec_z = Vec::new();
            let mut vec_r = Vec::new();
            for result in results.iter() {
                let (x, y, z) = result.0[idx].take();
                let r = result.1[idx];
                vec_x.push(x);
                vec_y.push(y);
                vec_z.push(z);
                vec_r.push(r);
            }
            let ss_x = ShamirSharings::create(vec_x);
            let ss_y = ShamirSharings::create(vec_y);
            let ss_z = ShamirSharings::create(vec_z);
            let ss_r = ShamirSharings::create(vec_r);

            let x = ss_x.reconstruct(threshold as usize);
            let y = ss_y.reconstruct(threshold as usize);
            let z = ss_z.reconstruct(threshold as usize);
            assert!(x.is_ok());
            assert!(y.is_ok());
            assert!(z.is_ok());
            assert_eq!(x.unwrap() * y.unwrap(), z.unwrap());
            let r = ss_r.reconstruct(threshold as usize);
            assert!(r.is_ok());
        }
    }

    #[test]
    fn test_pow_level_r() {
        let mut rng = AesRng::seed_from_u64(0);
        let exp = 1238501;
        let x = LevelR::sample(&mut rng);
        let x_pow = x.pow(LevelR::from_u128(exp));

        let mut res = LevelR::ONE;
        for _ in 0..exp {
            res *= x;
        }
        assert_eq!(res, x_pow);
    }
}
