use crate::{
    error::error_handler::anyhow_error_and_log,
    gf256,
    residue_poly::{ResiduePoly, F_DEG},
    Z128,
};
use gf256::GF256;
use std::num::Wrapping;

// Iterations needed for Newton Raphson inversion computation
const ITERATIONS: u32 = 8;
// Degree of polynomial we are working in
const D: u32 = F_DEG as u32;

// Expansion of inner loop needed for computing the initial value of x for Newton-Raphson.
// Computed using the following code:
// const TRACE_ONE: GF256 = GF256(42); // ... which is an element with trace 1
// fn compute_inner_loop() -> [GF256; 7] {
//     let delta_powers = two_powers(TRACE_ONE, D);
//     let mut inner_loop: [GF256; (D - 1) as usize] = [GF256(0); (D - 1) as usize];
//     for i in 0..(D - 1) {
//         let mut inner_temp = GF256::from(0);
//         for j in i + 1..D {
//             inner_temp += delta_powers[j as usize];
//         }
//         inner_loop[i as usize] = inner_temp;
//     }
//     inner_loop
// }
static INNER_LOOP: [GF256; 7] = [
    GF256(43),
    GF256(3),
    GF256(47),
    GF256(19),
    GF256(52),
    GF256(77),
    GF256(208),
];

/// Executes the `solve` algorithm of MPC-3, which is needed for random bit generation.
/// Concretely it takes an element t from Z_{2^128}[X]/x^8+x^4+x^3+x+1 which can be expressed as t=a+a^2.
/// The algorithm then returns x=a or x=a+1. That is, we observe that there are two possible solutions for x
/// and this method finds one of them, which will be equially and randomly distributed.
pub fn solve(a: ResiduePoly<Z128>) -> anyhow::Result<ResiduePoly<Z128>> {
    let one: ResiduePoly<Z128> = ResiduePoly::from_scalar(Wrapping::<u128>(1_u128));
    let two: ResiduePoly<Z128> = ResiduePoly::from_scalar(Wrapping::<u128>(2_u128));
    let mut y = one;
    let mut x = x_base(a)?;
    // Do outer Newton Raphson
    for _i in 1..ITERATIONS {
        // Do inner Newton Raphson to compute inverse of 1+2*x
        let z = one + two * x;
        y = y * (two - z * y);
        y = y * (two - z * y);
        x = y * (x * x + a);
    }
    // Validate the result, i.e. x+x^2 = input
    if a != x + x * x {
        return Err(anyhow_error_and_log(
            "The outer Newton Raphson inversion computation failed".to_string(),
        ));
    }
    Ok(x)
}

fn x_base(input: ResiduePoly<Z128>) -> anyhow::Result<ResiduePoly<Z128>> {
    let mut res = GF256::from(0);
    let v = ResiduePoly::<Z128>::bit_compose(&input, 0);
    let v_powers = two_powers(v, D - 1);
    for i in 0..(D - 1) {
        res += INNER_LOOP[i as usize] * v_powers[i as usize];
    }
    debug_assert_eq!(res + res * res, v);
    ResiduePoly::embed(res.0 as usize)
}

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
fn two_powers(input: GF256, max_power: u32) -> Vec<GF256> {
    let mut res = Vec::with_capacity(max_power as usize);
    let mut temp = input;
    res.push(temp);
    for _i in 1..max_power {
        temp = temp * temp;
        res.push(temp);
    }
    res
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use crate::{
        bit_generation::{solve, two_powers},
        gf256::GF256,
        residue_poly::ResiduePoly,
        Sample, Z128,
    };

    #[test]
    fn sunshine_sample() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let a = ResiduePoly::<Z128>::sample(&mut rng);
        let t = a + a * a;
        let x = match solve(t) {
            Ok(x) => x,
            Err(error) => panic!("Failed with error: {}", error),
        };
        assert_eq!(t, x + x * x);
    }

    #[test]
    fn negative_sample() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let a = ResiduePoly::<Z128>::sample(&mut rng);
        // The input is a pure square
        let t = a * a;
        if let Ok(x) = solve(a) {
            assert_ne!(t, x + x * x);
        }
    }

    #[test]
    fn two_power_sunshine() {
        let input = GF256::from(42);
        let powers = two_powers(input, 8);
        assert_eq!(8, powers.len());
        assert_eq!(42, powers[0].0);
        assert_eq!(input * input, powers[1]);
        assert_eq!(input * input * input * input, powers[2]);
        assert_eq!(
            input * input * input * input * input * input * input * input,
            powers[3]
        );
    }

    #[test]
    fn soak_sample() {
        let iterations = 1000;
        let mut rng = rand::thread_rng();
        let mut a: ResiduePoly<Z128>;
        let mut base_solutions = 0;
        for _i in 1..iterations {
            a = ResiduePoly::<Z128>::sample(&mut rng);
            let t = a + a * a;
            let x = match solve(t) {
                Ok(x) => x,
                Err(error) => panic!("Failed with error: {}", error),
            };
            assert_eq!(t, x + x * x);
            // Observe that the result will have two possible solutions, either x = a, or x = -a - 1
            if x == a {
                base_solutions += 1;
            }
        }
        // Check the results are within the expected variance
        assert!(base_solutions as f32 >= (iterations as f32) * 0.25);
        assert!(base_solutions as f32 <= (iterations as f32) * 0.75);
    }
}
