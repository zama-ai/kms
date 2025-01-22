use super::{
    poly::Poly,
    structure_traits::{Field, Ring},
};
use crate::algebra::bivariate::compute_powers_list;
use std::ops::Neg;

/// computes all polys L_i(Z) = \prod_{i \neq j} (Z - alpha_j) for the given list of points.
/// this is the numerator part of [lagrange_polynomials()]
pub fn lagrange_numerators<F: Ring + Neg<Output = F>>(points: &[F]) -> Vec<Poly<F>> {
    let polys: Vec<_> = points
        .iter()
        .enumerate()
        .map(|(i, _xi)| {
            let mut numerator = Poly::one();
            for (j, xj) in points.iter().enumerate() {
                if i != j {
                    numerator = numerator
                        * Poly {
                            coefs: vec![-*xj, F::ONE],
                        };
                }
            }
            numerator
        })
        .collect();
    polys
}

/// debug function that computes f(Z) = product_{p in points}(1 - pZ), only available in debug builds
#[cfg(debug_assertions)]
fn prod_alpha_z<F: Field>(points: &[F]) -> Poly<F> {
    tracing::info!("Computing check poly for points {:?}", points);
    // Empty products are treated as one
    let mut poly = Poly::one();
    for p in points {
        poly = poly
            * Poly {
                coefs: vec![F::ONE, -*p],
            };
    }
    tracing::info!("check is {:?}", poly);
    poly
}

/// computes a syndrome from a list of coordinates (x: alpha_i, y: c_i) and RS degree v = t + 1 in the field F
pub fn compute_syndrome<F: Field + std::fmt::Debug>(x_alpha: &[F], ci: &[F], v: usize) -> Poly<F> {
    assert_eq!(x_alpha.len(), ci.len());

    let n = ci.len();
    let r = n - v;
    tracing::info!("n:{n}, k:{v}, r:{r}");

    let lagrange_polys = lagrange_numerators(x_alpha);
    let alpha_powers = compute_powers_list(x_alpha, r);

    let mut syndrome = Poly::zeros(r);

    // compute each coefficient of the syndrome
    for j in 0..r {
        let mut coef = F::ZERO;

        for i in 0..n {
            let numerator = ci[i] * alpha_powers[i][j];
            let denom = lagrange_polys[i].eval(&x_alpha[i]);
            coef += numerator / denom;

            debug_assert_eq!(alpha_powers[i][1], x_alpha[i]);
        }

        syndrome.coefs[j] = coef;
    }
    syndrome
}

// sanity checks for debugging, only in debug builds
#[cfg(debug_assertions)]
fn sanity_check_decoding<F: Field>(
    sigma: Poly<F>,
    omega: Poly<F>,
    r: usize,
    bs: &[usize],
    e: &Vec<F>,
    lagrange_polys: &[Poly<F>],
    x_alpha: &[F],
) {
    let sigma_zero = sigma.eval(&F::ZERO);
    tracing::debug!("sigma(0): {:?}", sigma_zero);
    debug_assert_eq!(sigma_zero, F::ONE);
    tracing::debug!(
        "deg(sigma) = {:?}  -  deg(omega) = {:?}  |  r = {}",
        sigma.deg(),
        omega.deg(),
        r / 2
    );
    debug_assert!(sigma.deg() <= r / 2);
    debug_assert!(omega.deg() <= r / 2);

    // -- Check Sigma
    let f_bs: Vec<_> = bs.iter().map(|b| F::from_u128(*b as u128 + 1)).collect();
    let cs = prod_alpha_z(&f_bs);
    debug_assert_eq!(cs, sigma);

    // -- Check Omega
    let mut cw = Poly::zero();
    for b in bs {
        let factor = e[*b] / lagrange_polys[*b].eval(&x_alpha[*b]);

        let inner_bs: Vec<_> = bs
            .iter()
            .filter(|inner_b| *inner_b != b)
            .map(|b| F::from_u128(*b as u128 + 1))
            .collect();

        let poly = prod_alpha_z(&inner_bs);
        cw = cw + (poly * &factor);
    }
    debug_assert_eq!(cw, omega);

    tracing::info!("e {e:?}");
}

//NIST: Level Zero Operation
/// decode a given syndrome poly in the field for a given set of points and a RS value r = n - v.
pub fn decode_syndrome<F: Field>(syndrome: &Poly<F>, x_alpha: &[F], r: usize) -> Vec<F> {
    // nothing to decode if syndrome is zero, return all-zero error vector
    if syndrome == &Poly::zero() {
        return vec![F::ZERO; x_alpha.len()];
    }

    let (mut t0, mut t1) = (Poly::zero(), Poly::one());
    let mut r0 = Poly::zeros(r + 1);
    r0.coefs[r] = F::ONE; // R = Z^r
    let mut r1 = syndrome.clone();

    while r0.deg() >= r / 2 {
        let (q, _) = &r0 / &r1;
        (t0, t1) = (t1.clone(), t0 - (&q * t1));
        (r0, r1) = (r1.clone(), r0 - (&q * r1));
    }

    let sigma = &t0 / &t0.eval(&F::ZERO);
    let omega = &r0 / &t0.eval(&F::ZERO);

    // party indices (0-indexed) with errors
    let mut bs = Vec::new();
    for (idx, x) in x_alpha.iter().enumerate() {
        if sigma.eval(&x.invert()) == F::ZERO {
            bs.push(idx);
        }
    }

    // initialize error magnitudes to 0 for all indices
    let mut e = vec![F::ZERO; x_alpha.len()];
    let lagrange_polys = lagrange_numerators(x_alpha);

    // compute error magnitudes at indices b
    for b in bs.clone() {
        let alpha_b = x_alpha[b];
        let alpha_b_inv = alpha_b.invert();

        let numerator = -alpha_b * lagrange_polys[b].eval(&alpha_b) * omega.eval(&alpha_b_inv);
        let eb = numerator / sigma.formal_derivative().eval(&alpha_b_inv);
        e[b] = eb;
    }

    // sanity checks for debugging, only in debug builds
    #[cfg(debug_assertions)]
    sanity_check_decoding(sigma, omega, r, &bs, &e, &lagrange_polys, x_alpha);

    e
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "extension_degree_8")]
    use crate::algebra::galois_fields::gf256::GF256;
    #[cfg(feature = "extension_degree_3")]
    use crate::algebra::galois_fields::gf8::GF8;
    use crate::algebra::{
        galois_fields::gf16::GF16,
        poly::{gao_decoding, lagrange_interpolation},
    };

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_compute_syndrome_field_f8() {
        test_compute_syndrome_field::<GF256>(10)
    }

    #[test]
    fn test_compute_syndrome_field_f4() {
        test_compute_syndrome_field::<GF16>(10)
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_compute_syndrome_field_f3() {
        test_compute_syndrome_field::<GF8>(5)
    }

    fn test_compute_syndrome_field<BaseField: Field>(num_parties: u128) {
        let f = Poly {
            coefs: vec![BaseField::from_u128(7), BaseField::from_u128(42)],
        };

        let n = num_parties;
        let v = f.coefs.len(); //called k for RS codes in some literature, equals threshold + 1
        let r = n as usize - v;

        tracing::debug!("n={n}, v={v}, r={r}, detect={r}, correct={}", r / 2);

        let xs: Vec<_> = (1..=n).map(BaseField::from_u128).collect();
        let mut ys: Vec<_> = xs.iter().map(|x| f.eval(x)).collect();
        tracing::info!("cis plain: {:?}", ys);

        // syndrome should be zero without error
        let syndrome = compute_syndrome(&xs, &ys, v);
        tracing::info!("syndrome (ok): {:?}", syndrome);
        assert_eq!(syndrome, Poly::zeros(r));

        // with no errors we can just do plain Lagrange interpolation
        let l_poly = lagrange_interpolation(&xs, &ys).unwrap();
        for i in 1..=n {
            let l_i = l_poly.eval(&BaseField::from_u128(i));
            tracing::info!("interpolated L({i}) = {l_i:?}",);
            assert_eq!(l_i, ys[i as usize - 1]);
        }

        // add an error to the points
        ys[1] += BaseField::from_u128(7);
        tracing::info!("cis ERROR: {:?}", ys);

        // check that we can correct with one error
        let polynomial = gao_decoding(&xs, &ys, v, 1).unwrap();
        assert_eq!(
            polynomial.eval(&BaseField::from_u128(0)),
            BaseField::from_u128(7)
        );
        assert_eq!(polynomial, f);

        // syndrome should not be zero with errors
        let syndrome = compute_syndrome(&xs, &ys, v);
        tracing::info!("syndrome (xx): {:?}", syndrome);
        assert_ne!(syndrome, Poly::zeros(r));
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_syndrome_decode_field_f8() {
        test_syndrome_decode_field::<GF256>();
    }

    #[test]
    fn test_syndrome_decode_field_f4() {
        test_syndrome_decode_field::<GF16>();
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_syndrome_decode_field_f3() {
        test_syndrome_decode_field::<GF8>();
    }

    fn test_syndrome_decode_field<BaseField: Field>() {
        let f = Poly {
            coefs: vec![
                BaseField::from_u128(99),
                BaseField::from_u128(100),
                BaseField::from_u128(8),
            ],
        };

        let n = 7;
        let v = f.coefs.len(); //called k for RS codes in some literature, equals threshold + 1
        let r = n as usize - v;

        tracing::debug!("n={n}, v={v}, r=detect={r}, correct={}", r / 2);

        let xs: Vec<_> = (1..=n).map(BaseField::from_u128).collect();
        let mut ys: Vec<_> = xs.iter().map(|x| f.eval(x)).collect();

        // syndrome should be zero without error
        let syndrome = compute_syndrome(&xs, &ys, v);
        let e = decode_syndrome(&syndrome, &xs, r);
        tracing::info!("e (ok): {:?}", e);
        assert_eq!(e, vec![BaseField::ZERO; n as usize]); // test that e is all-zero

        // --- Errors added from here --
        let err_vals = [53, 54]; // must fit in a GF256 element
        let err_idxs = [3, 5]; // check indices below to now overflow

        // add one error to the points
        tracing::info!("Testing 1 Error...");
        ys[err_idxs[0]] += BaseField::from_u128(err_vals[0]);

        let syndrome = compute_syndrome(&xs, &ys, v);
        let e = decode_syndrome(&syndrome, &xs, r);
        tracing::info!("e (1x): {:?}", e);
        let mut reference = vec![BaseField::ZERO; n as usize];
        reference[err_idxs[0]] += BaseField::from_u128(err_vals[0]);
        assert_eq!(e, reference);

        // -- add a second error now
        tracing::info!("Testing 2 Errors...");
        ys[err_idxs[1]] += BaseField::from_u128(err_vals[1]);

        let syndrome = compute_syndrome(&xs, &ys, v);
        let e = decode_syndrome(&syndrome, &xs, r);
        tracing::info!("e (2x): {:?}", e);
        reference[err_idxs[1]] += BaseField::from_u128(err_vals[1]);
        assert_eq!(e, reference);
    }
}
