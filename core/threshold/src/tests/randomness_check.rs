//! This module implements some of the randomness checks described in
//! https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf

use statrs::function::{
    erf,
    gamma::{gamma, gamma_li},
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::algebra::structure_traits::Ring;

const SAMPLE_COUNT: usize = 100; // inverse of significance level
const SIGNIFICANCE_LEVEL: f64 = 1f64 / (SAMPLE_COUNT as f64);

/// Result of a randomness test.
/// Each test will produce a distinct result.
#[derive(Debug)]
pub struct RandomnessResult {
    samples: usize,
    passing: PassingProportion, // from proportion of sequence test (4.2.1)
    p_value_t: f64,             // from uniform distribution test (4.2.2)
}

impl RandomnessResult {
    /// Returns an error if the result is not accepted, i.e., not considered to be random.
    /// Ideally we need a lot of samples (> 1000) for this function to be accurate.
    pub fn check_result(&self) -> anyhow::Result<()> {
        // 4.2.1
        if self.passing.upper <= self.passing.proportion
            || self.passing.proportion <= self.passing.lower
        {
            anyhow::bail!(
                "not enough samples ({}) are passing ({:?})",
                self.samples,
                self.passing
            )
        }
        // 4.2.2
        if self.p_value_t < 0.0001 {
            anyhow::bail!("p_value_t={} is too small", self.p_value_t)
        }
        Ok(())
    }
}

#[derive(Debug, EnumIter)]
enum RandomnessTestType {
    Monobit,
    Runs,
}

/// Frequency (monobit) test, 2.1
fn monobit_test(stream: &[u8]) -> f64 {
    // It is recommended that each sequence to be tested consist of a minimum of 100 bits
    // so we assert that it's 12 bytes, i.e., 96 bits
    assert!(stream.len() >= 12);
    let mut sum = 0f64;
    let mut n = 0f64;
    for bytes in stream {
        for i in 0..8 {
            n += 1f64;
            let bit = (bytes >> i) & 1;
            sum += 2f64 * (bit as f64) - 1f64;
        }
    }

    let s_obs = sum.abs() / n.sqrt();
    erf::erfc(s_obs / 2f64.sqrt())
}

/// Runs test, 2.3
fn runs_test(stream: &[u8]) -> f64 {
    // It is recommended that each sequence to be tested consist of a minimum of 100 bits
    // so we assert that it's 12 bytes, i.e., 96 bits
    assert!(stream.len() >= 12);
    // compute frequency
    let mut ones = 0f64;
    let mut n = 0f64;
    let mut v_n_obs = 1f64;

    let mut first = true;
    let mut prev = 0u8;
    for bytes in stream {
        for i in 0..8 {
            let bit = (bytes >> i) & 1;
            ones += bit as f64;
            n += 1f64;

            if first {
                prev = bit;
            } else {
                if bit != prev {
                    v_n_obs += 1f64;
                }
                prev = bit;
            }
            first = false;
        }
    }

    let pi = ones / n;
    let tau = 2f64 / n.sqrt();
    if (pi - 0.5).abs() >= tau {
        // no need to be performed
        return 0f64;
    }

    let tmp = (v_n_obs - 2f64 * n * pi * (1f64 - pi)).abs()
        / (2f64 * (2f64 * n).sqrt() * pi * (1f64 - pi));
    erf::erfc(tmp)
}

#[derive(Debug)]
struct PassingProportion {
    upper: f64,
    lower: f64,
    proportion: f64,
}

/// Proportion of Sequences Passing a Test, 4.2.1
/// Also determine the range of accepted proportion.
fn passing_proportion(p_values: &[f64]) -> PassingProportion {
    let p_hat = 1.0 - SIGNIFICANCE_LEVEL;
    let m = p_values.len() as f64;

    let pass_count = p_values
        .iter()
        .filter(|p_value| **p_value >= SIGNIFICANCE_LEVEL)
        .count();

    let proportion = pass_count as f64 / m;

    let upper = p_hat + 3.0 * (p_hat * (1.0 - p_hat) / m).sqrt();
    let lower = p_hat - 3.0 * (p_hat * (1.0 - p_hat) / m).sqrt();

    PassingProportion {
        upper,
        lower,
        proportion,
    }
}

/// Incomplete gamma function, it has the property
/// igamc(a, 0) == 0, igamc(a, \inf) == 1
fn igamc(a: f64, x: f64) -> f64 {
    let gamma = gamma(a);
    gamma_li(a, x) / gamma
}

/// Uniform Distribution of P-values, 4.2.2
/// If the output P-value_T ≥ 0.0001, then the sequence is considered to be uniform
fn uniformity_of_p_values(p_values: &[f64]) -> f64 {
    // NIST recommends s >= 55
    let s = p_values.len() as f64;
    assert!(s >= 55.0);

    // we assume there are 10 BINS
    // 0..0.1, 0.1..0.2, ..., 0.9..1.0
    const BINS: usize = 10;

    // F_i
    let mut bin_count = vec![0usize; BINS];
    for p_value in p_values {
        for (i, bin) in bin_count.iter_mut().enumerate() {
            if *p_value < i as f64 * 0.1 + 0.1 {
                *bin += 1;
                break;
            }
        }
    }

    // X^2
    let x_squared = bin_count
        .into_iter()
        .map(|f_i| (f_i as f64 - s / 10.0).powf(2.0))
        .sum::<f64>()
        / (s / 10.0);

    igamc(9.0 / 2.0, x_squared / 2.0)
}

fn ring_test<F, Z: Ring>(test: F, elems: &[Z]) -> RandomnessResult
where
    F: Fn(&[u8]) -> f64,
{
    assert!(elems.len() >= SAMPLE_COUNT);
    let p_values = elems
        .iter()
        .map(|elem| test(&elem.to_byte_vec()))
        .collect::<Vec<_>>();

    RandomnessResult {
        samples: elems.len(),
        passing: passing_proportion(&p_values),
        p_value_t: uniformity_of_p_values(&p_values),
    }
}

/// Run the monobit test on a slice of ring elements.
pub fn ring_monobit_test<Z: Ring>(elems: &[Z]) -> RandomnessResult {
    assert!(elems.len() >= SAMPLE_COUNT);
    ring_test(monobit_test, elems)
}

/// Run the runs test on a slice of ring elements.
pub fn ring_runs_test<Z: Ring>(elems: &[Z]) -> RandomnessResult {
    assert!(elems.len() >= SAMPLE_COUNT);
    ring_test(runs_test, elems)
}

/// Execute all the randomness tests on a slice of ring elements.
pub fn execute_all_randomness_tests<Z: Ring>(elems: &[Z]) -> anyhow::Result<()> {
    for test_type in RandomnessTestType::iter() {
        let res = match test_type {
            RandomnessTestType::Monobit => ring_monobit_test(elems),
            RandomnessTestType::Runs => ring_runs_test(elems),
        };

        res.check_result()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::f64;

    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::{RngCore, SeedableRng};

    use crate::{
        algebra::{galois_rings::degree_4::ResiduePolyF4Z64, structure_traits::Sample},
        tests::randomness_check::{
            execute_all_randomness_tests, igamc, ring_monobit_test, ring_runs_test, runs_test,
            SIGNIFICANCE_LEVEL,
        },
    };

    use super::monobit_test;

    #[test]
    fn test_monobit() {
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
        // taken from 2.1.8 Example, which is 100 bits
        // but we work on bytes, so we need only take 12 bytes which is 96 bits
        // as such the computed p-value in the end does not match exactly
        {
            let z =
            0b_00001100_10010000_11111101_10101010_00100010_00010110_10001100_00100011_01001100_01001100_01100110_00101000_10111000_u128.to_be_bytes()[4..].to_vec();
            assert_eq!(z.len(), 12);
            let res = monobit_test(&z);
            assert!(res >= SIGNIFICANCE_LEVEL);
        }
        {
            let z = [1u8; 12];
            let res = monobit_test(&z);
            assert!(res < SIGNIFICANCE_LEVEL);
        }
        {
            // sanity check with AesRng
            let mut rng = AesRng::seed_from_u64(0);
            let mut z = [0u8; 12];
            rng.fill_bytes(&mut z);
            let res = monobit_test(&z);
            assert!(res >= SIGNIFICANCE_LEVEL);
        }
    }

    #[test]
    fn test_runs() {
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
        // taken from 2.1.8 Example, which is 100 bits
        // but we work on bytes, so we need only take 12 bytes which is 96 bits
        // as such the computed p-value in the end does not match exactly
        {
            let z =
            0b_00001100_10010000_11111101_10101010_00100010_00010110_10001100_00100011_01001100_01001100_01100110_00101000_10111000_u128.to_be_bytes()[4..].to_vec();
            assert_eq!(z.len(), 12);
            let res = runs_test(&z);
            assert!(res >= SIGNIFICANCE_LEVEL);
        }
        {
            let z = [1u8; 16];
            let res = monobit_test(&z);
            assert!(res < SIGNIFICANCE_LEVEL);
        }
        {
            // sanity check with AesRng
            let mut rng = AesRng::seed_from_u64(0);
            let mut z = [0u8; 12];
            rng.fill_bytes(&mut z);
            let res = runs_test(&z);
            assert!(res >= SIGNIFICANCE_LEVEL);
        }
    }

    #[test]
    fn test_monobit_for_residue_poly() {
        let mut rng = AesRng::seed_from_u64(1);
        const SAMPLES: usize = 1000;

        // should pass because all tests
        for _ in 0..100 {
            let all_residue_polys = (0..SAMPLES)
                .map(|_| ResiduePolyF4Z64::sample(&mut rng))
                .collect_vec();

            ring_monobit_test(&all_residue_polys)
                .check_result()
                .unwrap();
        }

        // negative testing
        for _ in 0..100 {
            let z = ResiduePolyF4Z64::sample(&mut rng);
            let all_residue_polys = (0..SAMPLES).map(|_| z).collect_vec();

            ring_monobit_test(&all_residue_polys)
                .check_result()
                .unwrap_err();
        }
    }

    #[test]
    fn test_runs_for_residue_poly() {
        let mut rng = AesRng::seed_from_u64(1);
        const SAMPLES: usize = 1000;

        // should pass because all tests
        for _ in 0..100 {
            let all_residue_polys = (0..SAMPLES)
                .map(|_| ResiduePolyF4Z64::sample(&mut rng))
                .collect_vec();

            ring_runs_test(&all_residue_polys).check_result().unwrap();
        }

        // negative testing
        for _ in 0..100 {
            let z = ResiduePolyF4Z64::sample(&mut rng);
            let all_residue_polys = (0..SAMPLES).map(|_| z).collect_vec();

            ring_runs_test(&all_residue_polys)
                .check_result()
                .unwrap_err();
        }
    }

    #[test]
    fn test_residue_polys() {
        let mut rng = AesRng::seed_from_u64(1);
        const SAMPLES: usize = 1000;

        // should pass all tests
        for _ in 0..100 {
            let all_residue_polys = (0..SAMPLES)
                .map(|_| ResiduePolyF4Z64::sample(&mut rng))
                .collect_vec();

            execute_all_randomness_tests(&all_residue_polys).unwrap();
        }

        // negative testing
        for _ in 0..100 {
            let z = ResiduePolyF4Z64::sample(&mut rng);
            let all_residue_polys = (0..SAMPLES).map(|_| z).collect_vec();

            execute_all_randomness_tests(&all_residue_polys).unwrap_err();
        }
    }

    #[test]
    fn test_igamc() {
        // igamc(a, 0) == 0
        let z = igamc(1.0 - f64::EPSILON, 0.0 + f64::EPSILON);
        assert!((0.0 - f64::EPSILON..=0.0 + f64::EPSILON).contains(&z));

        // igamc(a, \inf) == 1
        // note that f64::INFINITY fails the assert in statrs
        let z = igamc(1.0 - f64::EPSILON, f64::MAX);
        assert!((1.0 - f64::EPSILON..=1.0 + f64::EPSILON).contains(&z));
    }
}
