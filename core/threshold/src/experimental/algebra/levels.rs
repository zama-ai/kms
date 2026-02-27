use crate::algebra::error_correction::error_correction;
use crate::algebra::poly::lagrange_polynomials;
use crate::algebra::poly::Poly;
use crate::algebra::structure_traits::ErrorCorrect;
use crate::algebra::structure_traits::FromU128;
use crate::algebra::structure_traits::Invert;
use crate::algebra::structure_traits::Ring;
use crate::algebra::structure_traits::RingWithExceptionalSequence;
use crate::algebra::structure_traits::ZConsts;
use crate::algebra::structure_traits::{Field, One, Sample, Zero};
use crate::error::error_handler::anyhow_error_and_log;
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
use crypto_bigint::{U128, U1536, U192, U256, U320, U384, U448, U512, U576, U64, U640, U704, U768};
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
use crate::experimental::algebra::integers::{IntQ, ModReduction};
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

    fn get_self_modulus() -> Self;
}

#[derive(Hash, Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct GenericModulus<const LIMBS: usize>(pub Uint<LIMBS>);

pub type ModulusSize64 = GenericModulus<{ U64::LIMBS }>;
pub type ModulusSize128 = GenericModulus<{ U128::LIMBS }>;
pub type ModulusSize192 = GenericModulus<{ U192::LIMBS }>;
pub type ModulusSize256 = GenericModulus<{ U256::LIMBS }>;
pub type ModulusSize320 = GenericModulus<{ U320::LIMBS }>;
pub type ModulusSize384 = GenericModulus<{ U384::LIMBS }>;
pub type ModulusSize448 = GenericModulus<{ U448::LIMBS }>;
pub type ModulusSize512 = GenericModulus<{ U512::LIMBS }>;
pub type ModulusSize576 = GenericModulus<{ U576::LIMBS }>;
pub type ModulusSize640 = GenericModulus<{ U640::LIMBS }>;
pub type ModulusSize704 = GenericModulus<{ U704::LIMBS }>;
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

                fn get_self_modulus() -> Self {
                    Self {
                        value: GenericModulus(*Self::MODULUS.as_ref()),
                    }
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

            /// In-place negation if we have a mutable reference.
            impl Neg for &mut $name {
                type Output = ();

                fn neg(self) -> Self::Output {
                    self.value.0 = self.value.0.neg_mod(&$name::MODULUS);

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

        impl ModReduction<$name> for IntQ {
            fn mod_reduction(&self) -> $name {
                // assuming inputs are bounded by q since are computed from division
                let x: $uint_type = (&(self.data)).into();
                let cheap_mod = x.rem($name::MODULUS.as_nz_ref());

                if self.is_negative {
                    $name {
                        value: GenericModulus(cheap_mod.neg_mod(&$name::MODULUS)),
                    }
                } else {
                    $name {
                        value: GenericModulus(cheap_mod),
                    }
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

            impl RingWithExceptionalSequence for $name {
                fn get_from_exceptional_sequence(idx: usize) -> anyhow::Result<Self> {
                    let max_value : u128 = if Self::BIT_LENGTH < 128 {
                        1 << Self::BIT_LENGTH
                    }  else {
                        u128::MAX // For larger bit lengths, we use a max value that fits in u128
                    };

                    let idx = idx as u128;
                     if idx >= max_value {
                        return Err(anyhow_error_and_log(
                            format!("Index out of bounds for {} exceptional sequence", stringify!($name)),
                        ));
                    }

                    Ok(Self::from_u128(idx))
                }
            }

            impl ErrorCorrect for $name {
                fn error_correct(
                    sharing: &ShamirSharings<$name>,
                    threshold: usize,
                    max_errs: usize,
                ) -> anyhow::Result<Poly<$name>> {
                    error_correction(sharing.shares.clone(), threshold, max_errs)
                }
            }
            }
    };
}

impl RingWithExceptionalSequence for LevelKsw {
    // Field is big enough that we can use usize as index without any check
    fn get_from_exceptional_sequence(idx: usize) -> anyhow::Result<Self> {
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
        let mut res_level_r = FieldR::error_correct(&shamir_level_r, threshold, max_errs)?;

        let shamir_level_one = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_one))
                .collect_vec(),
        };
        let mut res_level_one = FieldOne::error_correct(&shamir_level_one, threshold, max_errs)?;

        let shamir_level_two = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_two))
                .collect_vec(),
        };
        let mut res_level_two = FieldTwo::error_correct(&shamir_level_two, threshold, max_errs)?;

        let shamir_level_three = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_three))
                .collect_vec(),
        };
        let mut res_level_three =
            FieldThree::error_correct(&shamir_level_three, threshold, max_errs)?;

        let shamir_level_four = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_four))
                .collect_vec(),
        };
        let mut res_level_four = FieldFour::error_correct(&shamir_level_four, threshold, max_errs)?;

        let shamir_level_five = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_five))
                .collect_vec(),
        };
        let mut res_level_five = FieldFive::error_correct(&shamir_level_five, threshold, max_errs)?;

        let shamir_level_six = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_six))
                .collect_vec(),
        };
        let mut res_level_six = FieldSix::error_correct(&shamir_level_six, threshold, max_errs)?;

        let shamir_level_seven = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_seven))
                .collect_vec(),
        };
        let mut res_level_seven =
            FieldSeven::error_correct(&shamir_level_seven, threshold, max_errs)?;

        let shamir_level_eight = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_eight))
                .collect_vec(),
        };
        let mut res_level_eight =
            FieldEight::error_correct(&shamir_level_eight, threshold, max_errs)?;

        let shamir_level_nine = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_nine))
                .collect_vec(),
        };
        let mut res_level_nine = FieldNine::error_correct(&shamir_level_nine, threshold, max_errs)?;

        let shamir_level_ten = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_ten))
                .collect_vec(),
        };
        let mut res_level_ten = FieldTen::error_correct(&shamir_level_ten, threshold, max_errs)?;

        let shamir_level_eleven = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_eleven))
                .collect_vec(),
        };
        let mut res_level_eleven =
            FieldEleven::error_correct(&shamir_level_eleven, threshold, max_errs)?;

        let shamir_level_twelve = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_twelve))
                .collect_vec(),
        };
        let mut res_level_twelve =
            FieldTwelve::error_correct(&shamir_level_twelve, threshold, max_errs)?;

        let shamir_level_thirteen = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_thirteen))
                .collect_vec(),
        };
        let mut res_level_thirteen =
            FieldThirteen::error_correct(&shamir_level_thirteen, threshold, max_errs)?;

        let shamir_level_fourteen = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_fourteen))
                .collect_vec(),
        };
        let mut res_level_fourteen =
            FieldFourteen::error_correct(&shamir_level_fourteen, threshold, max_errs)?;

        let shamir_level_fifteen = ShamirSharings {
            shares: crt_shares
                .iter()
                .map(|crt_share| Share::new(crt_share.1, crt_share.0.value_level_fifteen))
                .collect_vec(),
        };
        let mut res_level_fifteen =
            FieldFifteen::error_correct(&shamir_level_fifteen, threshold, max_errs)?;

        //All the level polynomial have max degree threshold, so we will crt reconstruct a polynomial of degree threshold
        let mut coefs: Vec<Self> = Vec::new();
        //Doing stuff in reverse order to get ownership with remove,
        //without having to pay for worst case complexity of moving all elements of the vector at every iteration
        for monomial_index in (0..=threshold).rev() {
            let value_level_one = if !res_level_one.coefs().is_empty()
                && res_level_one.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_one.pop().unwrap()
            } else {
                FieldOne::ZERO
            };

            let value_level_two = if !res_level_two.coefs().is_empty()
                && res_level_two.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_two.pop().unwrap()
            } else {
                FieldTwo::ZERO
            };

            let value_level_three = if !res_level_three.coefs().is_empty()
                && res_level_three.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_three.pop().unwrap()
            } else {
                FieldThree::ZERO
            };

            let value_level_four = if !res_level_four.coefs().is_empty()
                && res_level_four.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_four.pop().unwrap()
            } else {
                FieldFour::ZERO
            };

            let value_level_five = if !res_level_five.coefs().is_empty()
                && res_level_five.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_five.pop().unwrap()
            } else {
                FieldFive::ZERO
            };

            let value_level_six = if !res_level_six.coefs().is_empty()
                && res_level_six.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_six.pop().unwrap()
            } else {
                FieldSix::ZERO
            };

            let value_level_seven = if !res_level_seven.coefs().is_empty()
                && res_level_seven.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_seven.pop().unwrap()
            } else {
                FieldSeven::ZERO
            };

            let value_level_eight = if !res_level_eight.coefs().is_empty()
                && res_level_eight.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_eight.pop().unwrap()
            } else {
                FieldEight::ZERO
            };

            let value_level_nine = if !res_level_nine.coefs().is_empty()
                && res_level_nine.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_nine.pop().unwrap()
            } else {
                FieldNine::ZERO
            };

            let value_level_ten = if !res_level_ten.coefs().is_empty()
                && res_level_ten.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_ten.pop().unwrap()
            } else {
                FieldTen::ZERO
            };

            let value_level_eleven = if !res_level_eleven.coefs().is_empty()
                && res_level_eleven.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_eleven.pop().unwrap()
            } else {
                FieldEleven::ZERO
            };

            let value_level_twelve = if !res_level_twelve.coefs().is_empty()
                && res_level_twelve.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_twelve.pop().unwrap()
            } else {
                FieldTwelve::ZERO
            };

            let value_level_thirteen = if !res_level_thirteen.coefs().is_empty()
                && res_level_thirteen.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_thirteen.pop().unwrap()
            } else {
                FieldThirteen::ZERO
            };

            let value_level_fourteen = if !res_level_fourteen.coefs().is_empty()
                && res_level_fourteen.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_fourteen.pop().unwrap()
            } else {
                FieldFourteen::ZERO
            };

            let value_level_fifteen = if !res_level_fifteen.coefs().is_empty()
                && res_level_fifteen.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_fifteen.pop().unwrap()
            } else {
                FieldFifteen::ZERO
            };

            let value_level_r = if !res_level_r.coefs().is_empty()
                && res_level_r.coefs().len() - 1 == monomial_index
            {
                // SAFETY: length is checked before popping
                res_level_r.pop().unwrap()
            } else {
                FieldR::ZERO
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
        Ok(Poly::from_coefs(coefs))
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
            Err(anyhow_error_and_log(format!("Could not invert {self:?}")))
        } else {
            Ok(Self {
                value: GenericModulus(inverse.unwrap()),
            })
        }
    }
}

impl FieldR {
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
        let modulus_r: U1536 = FieldR::MODULUS.as_ref().into();
        Self {
            value: GenericModulus(v.value.0.rem(&NonZero::new(modulus_r).unwrap())),
        }
    }

    fn largest_prime_factor_non_zero(v: &Self) -> bool {
        let v_mod_largest_prime = Self::mod_largest_prime(v);
        v_mod_largest_prime != Self::ZERO
    }

    /// Projects a [`LevelKsw`] value onto the field defined by its largest prime factor [`FieldR::MODULUS`],
    /// and computes its square root.
    ///
    ///
    /// Uses the Tonelli-Shanks algorithm, which requires:
    /// - factoring [`FieldR::MODULUS`] - 1 as 2^S * Q with Q odd
    /// - finding a quadratic non-residue in the field defined by [`FieldR::MODULUS`]
    ///
    /// We can thus precomputes some values that are defined as constants:
    /// - ODD_DIV: corresponds to the Q in the factorisation above
    /// - ODD_DIV_PLUS_ONE_DIV_TWO: corresponds to (Q+1)/2
    /// - POW_2: corresponds to the S in the factorisation above
    /// - QUADRATIC_NON_RESIDUE_TO_ODD_DIV: corresponds to the quadratic non-residue above to the power Q
    fn largest_prime_factor_sqrt(v: &Self) -> Self {
        const ODD_DIV : FieldR = FieldR { value : GenericModulus(U768::from_be_hex("000020002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000350035")) };

        const ODD_DIV_PLUS_ONE_DIV_TWO : FieldR = FieldR { value : GenericModulus(U768::from_be_hex("0000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a801b")) };

        const QUADRATIC_NON_RESIDUE_TO_ODD_DIV: FieldR = FieldR { value : GenericModulus(U768::from_be_hex("1e528ea4b55cf66ce0de709f70f3e39d945dd63087c4a634a3eff8c36be27d36f6a32908b3b188874659e63e73aa3adf09eb0ffc153e24896a03d728776026ead7aa4eeea3e068077628d5f704364d9466b6ac2a5e3db6d328b1d7c98e407877")) };

        const POW_2: u128 = 17_u128;

        let modulus_r: U1536 = FieldR::MODULUS.as_ref().into();
        let value_level_r = FieldR {
            value: GenericModulus((&v.value.0.rem(&NonZero::new(modulus_r).unwrap())).into()),
        };

        let mut m = POW_2;
        let mut c = QUADRATIC_NON_RESIDUE_TO_ODD_DIV;
        let mut t = value_level_r.pow(ODD_DIV);
        let mut r = value_level_r.pow(ODD_DIV_PLUS_ONE_DIV_TWO);
        while t != FieldR::ONE {
            let i = {
                let mut i = 1;
                while t.pow(FieldR::from_u128(1 << i)) != FieldR::ONE {
                    i += 1;
                }
                assert!(i < m);
                i
            };

            let b = c.pow(FieldR::from_u128(1 << (m - i - 1)));
            c = b * b;
            t *= c;
            r *= b;
            m = i;
            assert!(t != FieldR::ZERO);
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

pub type Q = QProd15;
pub type LevelEll = LevelFifteen;

impl_modulus!(QR, U1536, "10fa17ff029785588e947e0014ed66262c5b572004af5d573b6da67287cb73539bf0dcbd5734053c99ad07c75dcd5e2d8125c199a141798bc05b440d4423fc3f32fcb578347bcb0a3811fcf2ad9ab871ca5802a42a617944735f2fb0a46b422b4edd36c0143ad73abc6b13ffe63776b14a366d36ab9ce50c9f51e5e982ac2b284c5c41204ea32f1775f400ab5870ad41123a581413911fbf7340413b0a8de8125fffabd64cd0af12ab664d1d07895be85eceb691e1f9e6bcfa1058020fa40001");
type ConstMontyFormQR = crypto_bigint::modular::ConstMontyForm<QR, { U1536::LIMBS }>;
impl_from_u128_big!(LevelKsw, U1536);
impl_ring_level!(LevelKsw, U1536, ModulusSize1536, QR, ConstMontyFormQR, "10fa17ff029785588e947e0014ed66262c5b572004af5d573b6da67287cb73539bf0dcbd5734053c99ad07c75dcd5e2d8125c199a141798bc05b440d4423fc3f32fcb578347bcb0a3811fcf2ad9ab871ca5802a42a617944735f2fb0a46b422b4edd36c0143ad73abc6b13ffe63776b14a366d36ab9ce50c9f51e5e982ac2b284c5c41204ea32f1775f400ab5870ad41123a581413911fbf7340413b0a8de8125fffabd64cd0af12ab664d1d07895be85eceb691e1f9e6bcfa1058020fa40000");

pub type FieldOne = LevelOne;
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

impl_modulus!(Q2, U64, "0001003500340001");
type ConstMontyFormQ2 = crypto_bigint::modular::ConstMontyForm<Q2, { U64::LIMBS }>;
impl_from_u128_small!(FieldTwo);
impl_field_level!(
    FieldTwo,
    U64,
    ModulusSize64,
    Q2,
    ConstMontyFormQ2,
    "0001003500340000"
);

impl_modulus!(
    QProd2,
    U192,
    "000000000000400d801a400d401444380835045900480001"
);
type ConstMontyFormQProd2 = crypto_bigint::modular::ConstMontyForm<QProd2, { U192::LIMBS }>;
impl_from_u128_big!(LevelTwo, U192);
impl_ring_level!(
    LevelTwo,
    U192,
    ModulusSize192,
    QProd2,
    ConstMontyFormQProd2,
    "000000000000400d801a400d401444380835045900480000"
);

impl_modulus!(Q3, U64, "0001005900580001");
type ConstMontyFormQ3 = crypto_bigint::modular::ConstMontyForm<Q3, { U64::LIMBS }>;
impl_from_u128_small!(FieldThree);
impl_field_level!(
    FieldThree,
    U64,
    ModulusSize64,
    Q3,
    ConstMontyFormQ3,
    "0001005900580000"
);

impl_modulus!(
    QProd3,
    U192,
    "4023c4e1cdd1cdc30fec06b4921e99aa9fd61d7200a00001"
);
type ConstMontyFormQProd3 = crypto_bigint::modular::ConstMontyForm<QProd3, { U192::LIMBS }>;
impl_from_u128_big!(LevelThree, U192);
impl_ring_level!(
    LevelThree,
    U192,
    ModulusSize192,
    QProd3,
    ConstMontyFormQProd3,
    "4023c4e1cdd1cdc30fec06b4921e99aa9fd61d7200a00000"
);

impl_modulus!(Q4, U64, "0001008300820001");
type ConstMontyFormQ4 = crypto_bigint::modular::ConstMontyForm<Q4, { U64::LIMBS }>;
impl_from_u128_small!(FieldFour);
impl_field_level!(
    FieldFour,
    U64,
    ModulusSize64,
    Q4,
    ConstMontyFormQ4,
    "0001008300820000"
);

impl_modulus!(
    QProd4,
    U256,
    "0000404497501f885aeda429775be423d6f17c6482c6d65be59b6f3501220001"
);
type ConstMontyFormQProd4 = crypto_bigint::modular::ConstMontyForm<QProd4, { U256::LIMBS }>;
impl_from_u128_big!(LevelFour, U256);
impl_ring_level!(
    LevelFour,
    U256,
    ModulusSize256,
    QProd4,
    ConstMontyFormQProd4,
    "0000404497501f885aeda429775be423d6f17c6482c6d65be59b6f3501220000"
);

impl_modulus!(Q5, U64, "0001009900980001");
type ConstMontyFormQ5 = crypto_bigint::modular::ConstMontyForm<Q5, { U64::LIMBS }>;
impl_from_u128_small!(FieldFive);
impl_field_level!(
    FieldFive,
    U64,
    ModulusSize64,
    Q5,
    ConstMontyFormQ5,
    "0001009900980000"
);

impl_modulus!(
    QProd5,
    U320,
    "00000000406b0074b7254b434c76b0c60d9bb315df5b5e5eb1d124fb7271a2759a671bfe01ba0001"
);
type ConstMontyFormQProd5 = crypto_bigint::modular::ConstMontyForm<QProd5, { U320::LIMBS }>;
impl_from_u128_big!(LevelFive, U320);
impl_ring_level!(
    LevelFive,
    U320,
    ModulusSize320,
    QProd5,
    ConstMontyFormQProd5,
    "00000000406b0074b7254b434c76b0c60d9bb315df5b5e5eb1d124fb7271a2759a671bfe01ba0000"
);

impl_modulus!(Q6, U64, "000100b700b60001");
type ConstMontyFormQ6 = crypto_bigint::modular::ConstMontyForm<Q6, { U64::LIMBS }>;
impl_from_u128_small!(FieldSix);
impl_field_level!(
    FieldSix,
    U64,
    ModulusSize64,
    Q6,
    ConstMontyFormQ6,
    "000100b700b60000"
);

impl_modulus!(QProd6, U384, "00000000000040990d1fd6a6ca514e8a929c12d466a7417567d7a58d382aab3f6e453e3d6dc06c10bcf356f102700001");
type ConstMontyFormQProd6 = crypto_bigint::modular::ConstMontyForm<QProd6, { U384::LIMBS }>;
impl_from_u128_big!(LevelSix, U384);
impl_ring_level!(LevelSix, U384, ModulusSize384, QProd6, ConstMontyFormQProd6, "00000000000040990d1fd6a6ca514e8a929c12d466a7417567d7a58d382aab3f6e453e3d6dc06c10bcf356f102700000");

impl_modulus!(Q7, U64, "0001010d010c0001");
type ConstMontyFormQ7 = crypto_bigint::modular::ConstMontyForm<Q7, { U64::LIMBS }>;
impl_from_u128_small!(FieldSeven);
impl_field_level!(
    FieldSeven,
    U64,
    ModulusSize64,
    Q7,
    ConstMontyFormQ7,
    "0001010d010c0000"
);

impl_modulus!(QProd7, U384, "40dcee3641555581a9b5bdfd2436f9c5682cba22b0b624c567c3d2249b91f00955d66e3871e9987f50f2e53e037c0001");
type ConstMontyFormQProd7 = crypto_bigint::modular::ConstMontyForm<QProd7, { U384::LIMBS }>;
impl_from_u128_big!(LevelSeven, U384);
impl_ring_level!(LevelSeven, U384, ModulusSize384, QProd7, ConstMontyFormQProd7, "40dcee3641555581a9b5bdfd2436f9c5682cba22b0b624c567c3d2249b91f00955d66e3871e9987f50f2e53e037c0000");

impl_modulus!(Q8, U64, "0001013501340001");
type ConstMontyFormQ8 = crypto_bigint::modular::ConstMontyForm<Q8, { U64::LIMBS }>;
impl_from_u128_small!(FieldEight);
impl_field_level!(
    FieldEight,
    U64,
    ModulusSize64,
    Q8,
    ConstMontyFormQ8,
    "0001013501340000"
);

impl_modulus!(QProd8, U448, "0000412b392fd2a10ba56818b7b0faedee6633951dd7ac2aca891f50ffb83e1ff2ff0ed470d8b2110933dde38583b411543c17a304b00001");
type ConstMontyFormQProd8 = crypto_bigint::modular::ConstMontyForm<QProd8, { U448::LIMBS }>;
impl_from_u128_big!(LevelEight, U448);
impl_ring_level!(LevelEight, U448, ModulusSize448, QProd8, ConstMontyFormQProd8, "0000412b392fd2a10ba56818b7b0faedee6633951dd7ac2aca891f50ffb83e1ff2ff0ed470d8b2110933dde38583b411543c17a304b00000");

impl_modulus!(Q9, U64, "0001014301420001");
type ConstMontyFormQ9 = crypto_bigint::modular::ConstMontyForm<Q9, { U64::LIMBS }>;
impl_from_u128_small!(FieldNine);
impl_field_level!(
    FieldNine,
    U64,
    ModulusSize64,
    Q9,
    ConstMontyFormQ9,
    "0001014301420000"
);

impl_modulus!(QProd9, U512, "00000000417d730af255fc29418b878eb9f6fd4e557f0a77233ec16255fdef8f12011a5dca8c09d3adaeb416e49ac0e34a9f53a562c47f05f958fe4605f20001");
type ConstMontyFormQProd9 = crypto_bigint::modular::ConstMontyForm<QProd9, { U512::LIMBS }>;
impl_from_u128_big!(LevelNine, U512);
impl_ring_level!(LevelNine, U512, ModulusSize512, QProd9, ConstMontyFormQProd9, "00000000417d730af255fc29418b878eb9f6fd4e557f0a77233ec16255fdef8f12011a5dca8c09d3adaeb416e49ac0e34a9f53a562c47f05f958fe4605f20000");

impl_modulus!(Q10, U64, "0001015301520001");
type ConstMontyFormQ10 = crypto_bigint::modular::ConstMontyForm<Q10, { U64::LIMBS }>;
impl_from_u128_small!(FieldTen);
impl_field_level!(
    FieldTen,
    U64,
    ModulusSize64,
    Q10,
    ConstMontyFormQ10,
    "0001015301520000"
);

impl_modulus!(QProd10, U576, "00000000000041d42c80c17709f794bf3421c2597b5cd3e36d15de0c9447fe8845e7971e92b769c3231b38407676b968edb94004b5546e060435e95747c673319143d91d07440001");
type ConstMontyFormQProd10 = crypto_bigint::modular::ConstMontyForm<QProd10, { U576::LIMBS }>;
impl_from_u128_big!(LevelTen, U576);
impl_ring_level!(LevelTen, U576, ModulusSize576, QProd10, ConstMontyFormQProd10, "00000000000041d42c80c17709f794bf3421c2597b5cd3e36d15de0c9447fe8845e7971e92b769c3231b38407676b968edb94004b5546e060435e95747c673319143d91d07440000");

impl_modulus!(Q11, U64, "0001016701660001");
type ConstMontyFormQ11 = crypto_bigint::modular::ConstMontyForm<Q11, { U64::LIMBS }>;
impl_from_u128_small!(FieldEleven);
impl_field_level!(
    FieldEleven,
    U64,
    ModulusSize64,
    Q11,
    ConstMontyFormQ11,
    "0001016701660000"
);

impl_modulus!(QProd11, U576, "42307d6738bcd5c947e97df4eb0b82cdd054d72da31e5863e22b71bc25bd3efcc3a1375ded06dab0a727d2265e00a6672bbb22bc62afd2966ec164a2ee5a170c6039039c08aa0001");
type ConstMontyFormQProd11 = crypto_bigint::modular::ConstMontyForm<QProd11, { U576::LIMBS }>;
impl_from_u128_big!(LevelEleven, U576);
impl_ring_level!(LevelEleven, U576, ModulusSize576, QProd11, ConstMontyFormQProd11, "42307d6738bcd5c947e97df4eb0b82cdd054d72da31e5863e22b71bc25bd3efcc3a1375ded06dab0a727d2265e00a6672bbb22bc62afd2966ec164a2ee5a170c6039039c08aa0000");

impl_modulus!(Q12, U64, "0001019101900001");
type ConstMontyFormQ12 = crypto_bigint::modular::ConstMontyForm<Q12, { U64::LIMBS }>;
impl_from_u128_small!(FieldTwelve);
impl_field_level!(
    FieldTwelve,
    U64,
    ModulusSize64,
    Q12,
    ConstMontyFormQ12,
    "0001019101900000"
);

impl_modulus!(QProd12, U640, "000042982bc31330e90d4ca865f06a4dc66e74a978b3b8f8e2900d3876f909b9f492d6fe3794920a68d0c7f148929502e88686810212c693da14a1da4f4e72551f804c02ae9b203596518ecd0a3a0001");
type ConstMontyFormQProd12 = crypto_bigint::modular::ConstMontyForm<QProd12, { U640::LIMBS }>;
impl_from_u128_big!(LevelTwelve, U640);
impl_ring_level!(LevelTwelve, U640, ModulusSize640, QProd12, ConstMontyFormQProd12, "000042982bc31330e90d4ca865f06a4dc66e74a978b3b8f8e2900d3876f909b9f492d6fe3794920a68d0c7f148929502e88686810212c693da14a1da4f4e72551f804c02ae9b203596518ecd0a3a0000");

impl_modulus!(Q13, U64, "0001019501940001");
type ConstMontyFormQ13 = crypto_bigint::modular::ConstMontyForm<Q13, { U64::LIMBS }>;
impl_from_u128_small!(FieldThirteen);
impl_field_level!(
    FieldThirteen,
    U64,
    ModulusSize64,
    Q13,
    ConstMontyFormQ13,
    "0001019501940000"
);

impl_modulus!(QProd13, U704, "00000000430186e966f397e073a5888792741f898a15996d8f2d7497dc96a59b016225fe93bb5937bdd800bd4a3f94d0567ff564d47d557a3a65ce1f07e54cd13009c9d1df9f17a66f5b63e9e1004d861fa8b3ea0bce0001");
type ConstMontyFormQProd13 = crypto_bigint::modular::ConstMontyForm<QProd13, { U704::LIMBS }>;
impl_from_u128_big!(LevelThirteen, U704);
impl_ring_level!(LevelThirteen, U704, ModulusSize704, QProd13, ConstMontyFormQProd13, "00000000430186e966f397e073a5888792741f898a15996d8f2d7497dc96a59b016225fe93bb5937bdd800bd4a3f94d0567ff564d47d557a3a65ce1f07e54cd13009c9d1df9f17a66f5b63e9e1004d861fa8b3ea0bce0000");

impl_modulus!(Q14, U64, "000101b301b20001");
type ConstMontyFormQ14 = crypto_bigint::modular::ConstMontyForm<Q14, { U64::LIMBS }>;
impl_from_u128_small!(FieldFourteen);
impl_field_level!(
    FieldFourteen,
    U64,
    ModulusSize64,
    Q14,
    ConstMontyFormQ14,
    "000101b301b20000"
);

impl_modulus!(QProd14, U768, "000000000000437362f33e24827d95eaec463753e456f23045c17c7f64a74f1fb237d3c21d24214fcb88f12b6b01bd4dbd9a150a84450890c1e2aaf6c6d09cb16273e859acfc8ca768d284b293fc87ff72e4b0fdcdf5bc07317bb8d90d800001");
type ConstMontyFormQProd14 = crypto_bigint::modular::ConstMontyForm<QProd14, { U768::LIMBS }>;
impl_from_u128_big!(LevelFourteen, U768);
impl_ring_level!(LevelFourteen, U768, ModulusSize768, QProd14, ConstMontyFormQProd14, "000000000000437362f33e24827d95eaec463753e456f23045c17c7f64a74f1fb237d3c21d24214fcb88f12b6b01bd4dbd9a150a84450890c1e2aaf6c6d09cb16273e859acfc8ca768d284b293fc87ff72e4b0fdcdf5bc07317bb8d90d800000");

impl_modulus!(Q15, U64, "000101bb01ba0001");
type ConstMontyFormQ15 = crypto_bigint::modular::ConstMontyForm<Q15, { U64::LIMBS }>;
impl_from_u128_small!(FieldFifteen);
impl_field_level!(
    FieldFifteen,
    U64,
    ModulusSize64,
    Q15,
    ConstMontyFormQ15,
    "000101bb01ba0000"
);

impl_modulus!(QProd15, U768, "43e81c13ee4a27181339e4c66eef29a987c3d4bc3e01375bb65ae36f3bbe918fde3394c1c80e4ce419d0054d71e806cdfdc9089d7c6869c697a6788e980158fb72f762e96f05bd232324d0a5e5c4fc022d5ddd32cc5318beb4be09940f3a0001");
type ConstMontyFormQProd15 = crypto_bigint::modular::ConstMontyForm<QProd15, { U768::LIMBS }>;
impl_from_u128_big!(LevelFifteen, U768);
impl_ring_level!(LevelFifteen, U768, ModulusSize768, QProd15, ConstMontyFormQProd15, "43e81c13ee4a27181339e4c66eef29a987c3d4bc3e01375bb65ae36f3bbe918fde3394c1c80e4ce419d0054d71e806cdfdc9089d7c6869c697a6788e980158fb72f762e96f05bd232324d0a5e5c4fc022d5ddd32cc5318beb4be09940f3a0000");

impl_modulus!(R, U768, "400040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a006a0001");
type ConstMontyFormR = crypto_bigint::modular::ConstMontyForm<R, { U768::LIMBS }>;
impl_from_u128_big!(FieldR, U768);
impl_field_level!(FieldR, U768, ModulusSize768, R, ConstMontyFormR, "400040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a006a0000");

/// Scaling factor is R from T = QR in the NIST document, but using the same underlying type as QR.
pub trait ScalingFactor {
    const FACTOR: Self;
}

impl ScalingFactor for LevelKsw {
    const FACTOR: Self = Self{value : GenericModulus(U1536::from_be_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a006a0001"))};
}

#[cfg(test)]
mod tests {
    use crate::algebra::poly::lagrange_interpolation;
    use crate::execution::config::BatchParams;
    use crate::execution::online::preprocessing::{RandomPreprocessing, TriplePreprocessing};
    use crate::execution::runtime::party::Role;
    use crate::execution::runtime::sessions::small_session::SmallSession;
    use crate::execution::sharing::shamir::{InputOp, RevealOp};
    use crate::execution::sharing::shamir::{ShamirFieldPoly, ShamirSharings};
    use crate::execution::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
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
        let poly = Poly::from_coefs(vec![LevelOne::from_u128(11), LevelOne::from_u128(1)]);
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
        let poly = Poly::from_coefs(vec![
            LevelOne::from_u128(11),
            LevelOne::from_u128(2),
            LevelOne::from_u128(3),
            LevelOne::from_u128(22),
            LevelOne::from_u128(9),
        ]);
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
        let f = ShamirFieldPoly::<LevelOne>::from_coefs(vec![
            LevelOne::from_u128(12345),
            LevelOne::from_u128(1234567),
            LevelOne::from_u128(12345678910),
        ]);

        let num_parties = 7;
        let threshold = f.coefs().len() - 1; // = 2 here
        let max_err = (num_parties - threshold) / 2; // = 2 here

        let mut shares: Vec<_> = (1..=num_parties)
            .map(|x| {
                let party = Role::indexed_from_one(x);
                let point = f.eval(&LevelOne::embed_role_to_exceptional_sequence(&party).unwrap());
                Share::<LevelOne>::new(party, point)
            })
            .collect();

        // modify shares of parties 1 and 2
        shares[1] += LevelOne::from_u128(10);
        shares[2] += LevelOne::from_u128(254);

        let secret_poly = error_correction(shares, threshold, max_err).unwrap();
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

    #[tokio::test]
    async fn test_levelksw_triple_gen() {
        let parties = 5;
        let threshold = 1;
        let mut task = |mut session: SmallSession<LevelKsw>, _bot: Option<String>| async move {
            let batch_size = BatchParams {
                triples: 100,
                randoms: 100,
            };

            let mut prep = SecureSmallPreprocessing::default()
                .execute(&mut session, batch_size)
                .await
                .unwrap();
            (
                prep.next_triple_vec(100).unwrap(),
                prep.next_random_vec(100).unwrap(),
            )
        };
        //This is Sync because we are generating triples
        let results = execute_protocol_small::<_, _, _, { LevelKsw::EXTENSION_DEGREE }>(
            parties,
            threshold,
            None,
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        )
        .await;

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
        let x = FieldR::sample(&mut rng);
        let x_pow = x.pow(FieldR::from_u128(exp));

        let mut res = FieldR::ONE;
        for _ in 0..exp {
            res *= x;
        }
        assert_eq!(res, x_pow);
    }
}
