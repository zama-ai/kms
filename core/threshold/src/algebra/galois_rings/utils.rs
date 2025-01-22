use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use serde::{
    de::{SeqAccess, Visitor},
    Deserialize,
};

// Taken from https://github.com/serde-rs/serde/issues/1937#issuecomment-812137971
// because we can not derive Serialize and Deserialize for arrays of generic size
pub(crate) struct ArrayVisitor<T, const N: usize>(pub(crate) PhantomData<T>);

impl<'de, T, const N: usize> Visitor<'de> for ArrayVisitor<T, N>
where
    T: Deserialize<'de>,
{
    type Value = [T; N];

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!("an array of length {}", N))
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // can be optimized using MaybeUninit
        let mut data = Vec::with_capacity(N);
        for _ in 0..N {
            match (seq.next_element())? {
                Some(val) => data.push(val),
                None => return Err(serde::de::Error::invalid_length(N, &self)),
            }
        }
        match data.try_into() {
            Ok(arr) => Ok(arr),
            Err(_) => unreachable!(),
        }
    }
}

// KARATSUBA MULTIPLICATION

/* (a1*X+a0)*(b1*X+b0) */
#[cfg(any(
    feature = "extension_degree_3",
    feature = "extension_degree_4",
    feature = "extension_degree_5",
    feature = "extension_degree_6",
    feature = "extension_degree_7",
    feature = "extension_degree_8",
))]
pub(crate) fn karatsuba_2<Z>(a: &[Z], b: &[Z]) -> [Z; 3]
where
    Z: Add<Z, Output = Z>,
    Z: Mul<Z, Output = Z>,
    Z: Sub<Z, Output = Z>,
    Z: Copy,
{
    debug_assert_eq!(a.len(), 2);
    debug_assert_eq!(b.len(), 2);
    let z0 = a[1] * b[1];
    let z2 = a[0] * b[0];
    let z3 = (a[0] + a[1]) * (b[0] + b[1]);
    let z1 = z3 - z2 - z0;

    [z2, z1, z0]
}

/*  (a2*X^2+a1*X+a0)*(b2*X^2+b1*X+b0) */
#[cfg(any(
    feature = "extension_degree_3",
    feature = "extension_degree_5",
    feature = "extension_degree_6",
    feature = "extension_degree_7"
))]
pub(crate) fn karatsuba_3<Z>(a: &[Z], b: &[Z]) -> [Z; 5]
where
    Z: Add<Z, Output = Z>,
    Z: Mul<Z, Output = Z>,
    Z: Sub<Z, Output = Z>,
    Z: Copy,
{
    debug_assert_eq!(a.len(), 3);
    debug_assert_eq!(b.len(), 3);
    let z0 = karatsuba_2(&a[1..=2], &b[1..=2]);
    let z2 = a[0] * b[0];
    let z3 = karatsuba_2(&[a[1], a[0] + a[2]], &[b[1], b[0] + b[2]]);
    let z1 = [z3[0] - z0[0], z3[1] - z0[1], z3[2] - z2 - z0[2]];
    [z2 + z1[0], z1[1], z1[2] + z0[0], z0[1], z0[2]]
}

/* (a3*X^3+a2*X^2+a1*X+a0)*(b3*X^3+b2*X^2+b1*X+b0) */
#[cfg(any(
    feature = "extension_degree_4",
    feature = "extension_degree_7",
    feature = "extension_degree_8",
))]
pub(crate) fn karatsuba_4<Z>(a: &[Z], b: &[Z]) -> [Z; 7]
where
    Z: Add<Z, Output = Z>,
    Z: Mul<Z, Output = Z>,
    Z: Sub<Z, Output = Z>,
    Z: Copy,
{
    debug_assert_eq!(a.len(), 4);
    debug_assert_eq!(b.len(), 4);
    let z0 = karatsuba_2(&a[2..=3], &b[2..=3]);
    let z2 = karatsuba_2(&a[0..=1], &b[0..=1]);
    let z3 = karatsuba_2(&[a[0] + a[2], a[1] + a[3]], &[b[0] + b[2], b[1] + b[3]]);
    let z1 = [
        z3[0] - z2[0] - z0[0],
        z3[1] - z2[1] - z0[1],
        z3[2] - z2[2] - z0[2],
    ];
    [
        z2[0],
        z2[1],
        z2[2] + z1[0],
        z1[1],
        z1[2] + z0[0],
        z0[1],
        z0[2],
    ]
}

/* (a4*X^4+3*X^3+a2*X^2+a1*X+a0)*(b4*X^4+b3*X^3+b2*X^2+b1*X+b0) */
#[cfg(feature = "extension_degree_5")]
#[allow(dead_code)]
pub(crate) fn karatsuba_5<Z>(a: &[Z], b: &[Z]) -> [Z; 9]
where
    Z: Add<Z, Output = Z>,
    Z: Mul<Z, Output = Z>,
    Z: Sub<Z, Output = Z>,
    Z: Copy,
{
    debug_assert_eq!(a.len(), 5);
    debug_assert_eq!(b.len(), 5);
    let z0 = karatsuba_3(&a[2..=4], &b[2..=4]);
    let z2 = karatsuba_2(&a[0..=1], &b[0..=1]);
    let z3 = karatsuba_3(
        &[a[2], a[0] + a[3], a[1] + a[4]],
        &[b[2], b[0] + b[3], b[1] + b[4]],
    );
    let z1 = [
        z3[0] - z0[0],
        z3[1] - z0[1],
        z3[2] - z2[0] - z0[2],
        z3[3] - z2[1] - z0[3],
        z3[4] - z2[2] - z0[4],
    ];
    [
        z2[0],
        z2[1] + z1[0],
        z2[2] + z1[1],
        z1[2],
        z1[3] + z0[0],
        z1[4] + z0[1],
        z0[2],
        z0[3],
        z0[4],
    ]
}

/* (a5*X^5+a4*X^4+a3*X^3+a2*X^2+a1*X+a0)*(b5*X^5+b4*X^4+b3*X^3+b2*X^2+b1*X+b0) */
#[cfg(feature = "extension_degree_6")]
#[allow(dead_code)]
pub(crate) fn karatsuba_6<Z>(a: &[Z], b: &[Z]) -> [Z; 11]
where
    Z: Add<Z, Output = Z>,
    Z: Mul<Z, Output = Z>,
    Z: Sub<Z, Output = Z>,
    Z: Copy,
{
    debug_assert_eq!(a.len(), 6);
    debug_assert_eq!(b.len(), 6);
    let z0 = karatsuba_3(&a[3..=5], &b[3..=5]);
    let z2 = karatsuba_3(&a[0..=2], &b[0..=2]);
    let z3 = karatsuba_3(
        &[a[0] + a[3], a[1] + a[4], a[2] + a[5]],
        &[b[0] + b[3], b[1] + b[4], b[2] + b[5]],
    );
    let z1 = [
        z3[0] - z2[0] - z0[0],
        z3[1] - z2[1] - z0[1],
        z3[2] - z2[2] - z0[2],
        z3[3] - z2[3] - z0[3],
        z3[4] - z2[4] - z0[4],
    ];
    [
        z2[0],
        z2[1],
        z2[2],
        z2[3] + z1[0],
        z2[4] + z1[1],
        z1[2],
        z1[3] + z0[0],
        z1[4] + z0[1],
        z0[2],
        z0[3],
        z0[4],
    ]
}

/* (a6*X^6+a5*X^5+a4*X^4+a3*X^3+a2*X^2+a1*X+a0)*(b6*X^6+b5*X^5+b4*X^4+b3*X^3+b2*X^2+b1*X+b0) */
#[cfg(feature = "extension_degree_7")]
#[allow(dead_code)]
pub(crate) fn karatsuba_7<Z>(a: &[Z], b: &[Z]) -> [Z; 13]
where
    Z: Add<Z, Output = Z>,
    Z: Mul<Z, Output = Z>,
    Z: Sub<Z, Output = Z>,
    Z: Copy,
{
    debug_assert_eq!(a.len(), 7);
    debug_assert_eq!(b.len(), 7);
    let z0 = karatsuba_4(&a[3..=6], &b[3..=6]);
    let z2 = karatsuba_3(&a[0..=2], &b[0..=2]);
    let z3 = karatsuba_4(
        &[a[3], a[0] + a[4], a[1] + a[5], a[2] + a[6]],
        &[b[3], b[0] + b[4], b[1] + b[5], b[2] + b[6]],
    );
    let z1 = [
        z3[0] - z0[0],
        z3[1] - z0[1],
        z3[2] - z2[0] - z0[2],
        z3[3] - z2[1] - z0[3],
        z3[4] - z2[2] - z0[4],
        z3[5] - z2[3] - z0[5],
        z3[6] - z2[4] - z0[6],
    ];
    [
        z2[0],
        z2[1],
        z1[0] + z2[2],
        z1[1] + z2[3],
        z1[2] + z2[4],
        z1[3],
        z1[4] + z0[0],
        z1[5] + z0[1],
        z1[6] + z0[2],
        z0[3],
        z0[4],
        z0[5],
        z0[6],
    ]
}

/* (a7*X^7+a6*X^6+a5*X^5+a4*X^4+a3*X^3+a2*X^2+a1*X+a0)*(b7*X^7+b6*X^6+b5*X^5+b4*X^4+b3*X^3+b2*X^2+b1*X+b0) */
#[cfg(feature = "extension_degree_8")]
pub(crate) fn karatsuba_8<Z>(a: &[Z], b: &[Z]) -> [Z; 15]
where
    Z: Add<Z, Output = Z>,
    Z: Mul<Z, Output = Z>,
    Z: Sub<Z, Output = Z>,
    Z: Copy,
{
    debug_assert_eq!(a.len(), 8);
    debug_assert_eq!(b.len(), 8);
    let z0 = karatsuba_4(&a[4..=7], &b[4..=7]);
    let z2 = karatsuba_4(&a[0..=3], &b[0..=3]);
    let z3 = karatsuba_4(
        &[a[0] + a[4], a[1] + a[5], a[2] + a[6], a[3] + a[7]],
        &[b[0] + b[4], b[1] + b[5], b[2] + b[6], b[3] + b[7]],
    );
    let z1 = [
        z3[0] - z2[0] - z0[0],
        z3[1] - z2[1] - z0[1],
        z3[2] - z2[2] - z0[2],
        z3[3] - z2[3] - z0[3],
        z3[4] - z2[4] - z0[4],
        z3[5] - z2[5] - z0[5],
        z3[6] - z2[6] - z0[6],
    ];
    [
        z2[0],
        z2[1],
        z2[2],
        z2[3],
        z1[0] + z2[4],
        z1[1] + z2[5],
        z1[2] + z2[6],
        z1[3],
        z1[4] + z0[0],
        z1[5] + z0[1],
        z1[6] + z0[2],
        z0[3],
        z0[4],
        z0[5],
        z0[6],
    ]
}

#[cfg(test)]
mod tests {
    use std::{
        num::Wrapping,
        ops::{AddAssign, Mul},
    };

    use super::karatsuba_2;
    #[cfg(feature = "extension_degree_3")]
    use super::karatsuba_3;
    #[cfg(feature = "extension_degree_4")]
    use super::karatsuba_4;
    #[cfg(feature = "extension_degree_5")]
    use super::karatsuba_5;
    #[cfg(feature = "extension_degree_6")]
    use super::karatsuba_6;
    #[cfg(feature = "extension_degree_7")]
    use super::karatsuba_7;
    #[cfg(feature = "extension_degree_8")]
    use super::karatsuba_8;
    use crate::algebra::structure_traits::Zero;

    fn naive_mult<Z>(a: &[Z], b: &[Z]) -> Vec<Z>
    where
        Z: Mul<Z, Output = Z>,
        Z: AddAssign<Z>,
        Z: Zero,
        Z: Copy,
    {
        let degree = a.len() - 1;
        let mut res = vec![Z::ZERO; 2 * a.len() - 1];
        for i in 0..=degree {
            for j in 0..=degree {
                res[i + j] += a[i] * b[j];
            }
        }
        res
    }

    proptest::proptest! {
        #[test]
        fn test_karatsuba_2((a, b) in (
            proptest::arbitrary::any::<[Wrapping<u64>;2]>(),
            proptest::arbitrary::any::<[Wrapping<u64>;2]>(),
        ))  {

            let c = naive_mult(&a, &b);
            let d = karatsuba_2(&a, &b);
            assert_eq!(d.to_vec(), c)

        }

        #[cfg(feature = "extension_degree_3")]
        #[test]
        fn test_karatsuba_3((a, b) in (
            proptest::arbitrary::any::<[Wrapping<u64>;3]>(),
            proptest::arbitrary::any::<[Wrapping<u64>;3]>(),
        ))  {

            let c = naive_mult(&a, &b);
            let d = karatsuba_3(&a, &b);
            assert_eq!(d.to_vec(), c)

        }

        #[cfg(feature = "extension_degree_4")]
        #[test]
        fn test_karatsuba_4((a, b) in (
            proptest::arbitrary::any::<[Wrapping<u64>;4]>(),
            proptest::arbitrary::any::<[Wrapping<u64>;4]>(),
        ))  {

            let c = naive_mult(&a, &b);
            let d = karatsuba_4(&a, &b);
            assert_eq!(d.to_vec(), c)

        }

        #[cfg(feature = "extension_degree_5")]
        #[test]
        fn test_karatsuba_5((a, b) in (
            proptest::arbitrary::any::<[Wrapping<u64>;5]>(),
            proptest::arbitrary::any::<[Wrapping<u64>;5]>(),
        ))  {

            let c = naive_mult(&a, &b);
            let d = karatsuba_5(&a, &b);
            assert_eq!(d.to_vec(), c)

        }

        #[cfg(feature = "extension_degree_6")]
        #[test]
        fn test_karatsuba_6((a, b) in (
            proptest::arbitrary::any::<[Wrapping<u64>;6]>(),
            proptest::arbitrary::any::<[Wrapping<u64>;6]>(),
        ))  {

            let c = naive_mult(&a, &b);
            let d = karatsuba_6(&a, &b);
            assert_eq!(d.to_vec(), c)

        }

        #[cfg(feature = "extension_degree_7")]
        #[test]
        fn test_karatsuba_7((a, b) in (
            proptest::arbitrary::any::<[Wrapping<u64>;7]>(),
            proptest::arbitrary::any::<[Wrapping<u64>;7]>(),
        ))  {

            let c = naive_mult(&a, &b);
            let d = karatsuba_7(&a, &b);
            assert_eq!(d.to_vec(), c)

        }

        #[cfg(feature = "extension_degree_8")]
        #[test]
        fn test_karatsuba_8((a, b) in (
            proptest::arbitrary::any::<[Wrapping<u64>;8]>(),
            proptest::arbitrary::any::<[Wrapping<u64>;8]>(),
        ))  {

            let c = naive_mult(&a, &b);
            let d = karatsuba_8(&a, &b);
            assert_eq!(d.to_vec(), c)

        }
    }
}
