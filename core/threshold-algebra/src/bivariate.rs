use super::poly::Poly;
use super::structure_traits::Ring;
use super::structure_traits::Sample;

use rand::{CryptoRng, Rng};

/// Bivariate polynomial represented as a row-major square matrix of coefficients.
///
/// The row view of the polynomials is the following:
/// [[a_{00}, a_{01}, ..., a_{0d}], ..., [a_{d0}, ..., a_{dd}]]
///
/// Constructors establish and maintain the invariant `coefs.len() == (degree + 1)^2`,
/// so every row in `coefs.chunks_exact(degree + 1)` has exactly `degree + 1` entries.
#[derive(Clone, Debug)]
pub struct BivariatePoly<Z> {
    /// Row-major; `(degree + 1)^2` elements.
    coefs: Vec<Z>,
    degree: usize,
}

impl<Z> BivariatePoly<Z> {
    /// Samples a random bivariate polynomial where the free term is the secret.
    pub fn from_secret<R: Rng + CryptoRng>(rng: &mut R, secret: Z, degree: usize) -> Self
    where
        Z: Sample,
    {
        let d = degree + 1;
        let n = d * d;
        let mut coefs = Vec::with_capacity(n);
        coefs.push(secret);
        coefs.extend((1..n).map(|_| Z::sample(rng)));

        BivariatePoly { coefs, degree }
    }

    #[cfg(test)]
    fn from_coeffs(coefs: Vec<Z>, degree: usize) -> Self {
        let d = degree + 1;
        assert_eq!(coefs.len(), d * d);
        BivariatePoly { coefs, degree }
    }

    fn dim(&self) -> usize {
        self.degree + 1
    }

    fn coeffs(&self) -> &[Z] {
        &self.coefs
    }
}

impl<Z: Ring> BivariatePoly<Z> {
    /// Given a degree T bivariate poly F(X,Y) = sum a_ij X^i Y^j and a point \alpha, evaluate the X variable:
    /// G(Y) = F(\alpha, Y) with coefficients [sum_i a_i0 \alpha^i, ..., sum_i a_id \alpha^i].
    pub fn partial_x_evaluation(&self, alpha: Z) -> Poly<Z> {
        let d = self.dim();
        let coefs = self.coeffs();
        let mut res = coefs[(d - 1) * d..d * d].to_vec();
        // Every row has exactly `d` coefficients.
        for row in coefs[..(d - 1) * d].chunks_exact(d).rev() {
            for (res_coef, coef) in res.iter_mut().zip(row) {
                *res_coef = *res_coef * alpha + *coef;
            }
        }
        Poly::from_coefs(res)
    }

    /// Given a degree T bivariate poly F(X,Y) = sum a_ij X^i Y^j and a point \alpha, evaluate the Y variable:
    /// G(X) = F(X, \alpha) with coefficients [sum_j a_0j \alpha^j, ..., sum_j a_dj \alpha^j].
    pub fn partial_y_evaluation(&self, alpha: Z) -> Poly<Z> {
        let d = self.dim();
        let coefs = self.coeffs();
        let mut res = Vec::with_capacity(d);
        // Each pass consumes exactly one row of length `d`.
        for row in coefs.chunks_exact(d) {
            let mut acc = row[d - 1];
            for coef in row[..d - 1].iter().rev() {
                acc = acc * alpha + *coef;
            }
            res.push(acc);
        }
        Poly::from_coefs(res)
    }

    /// Compute both partial evaluations at the same point.
    ///
    /// Returns `(F(\alpha, Y), F(X, \alpha))`, matching
    /// [`Self::partial_x_evaluation`] and [`Self::partial_y_evaluation`].
    pub fn partial_evaluations(&self, alpha: Z) -> (Poly<Z>, Poly<Z>) {
        let d = self.dim();
        let coefs = self.coeffs();
        let last_row_start = (d - 1) * d;
        let last_row = &coefs[last_row_start..last_row_start + d];

        let mut partial_x = last_row.to_vec();
        let mut partial_y = vec![Z::ZERO; d];

        let mut acc = last_row[d - 1];
        for coef in last_row[..d - 1].iter().rev() {
            acc = acc * alpha + *coef;
        }
        partial_y[d - 1] = acc;

        // Computes both directions in one pass to avoid repeating the row scan.
        for (row_idx, row) in coefs[..last_row_start].chunks_exact(d).enumerate().rev() {
            let mut acc = row[d - 1];
            for coef in row[..d - 1].iter().rev() {
                acc = acc * alpha + *coef;
            }
            partial_y[row_idx] = acc;

            for (res_coef, coef) in partial_x.iter_mut().zip(row) {
                *res_coef = *res_coef * alpha + *coef;
            }
        }

        (Poly::from_coefs(partial_x), Poly::from_coefs(partial_y))
    }

    /// Given a degree T bivariate poly F(X,Y) and two points \alpha_x, \alpha_y, we compute
    /// F(\alpha_x, \alpha_y)
    pub fn full_evaluation(&self, alpha_x: Z, alpha_y: Z) -> Z {
        let d = self.dim();
        let coefs = self.coeffs();
        let mut acc = Z::ZERO;
        let mut alpha_x_power = Z::ONE;
        for row in coefs.chunks_exact(d) {
            let mut row_acc = row[d - 1];
            for coef in row[..d - 1].iter().rev() {
                row_acc = row_acc * alpha_y + *coef;
            }
            acc += alpha_x_power * row_acc;
            alpha_x_power *= alpha_x;
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "extension_degree_8")]
    use crate::galois_rings::degree_8::ResiduePolyF8Z128;
    use crate::{
        galois_rings::{
            common::ResiduePoly,
            degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        },
        structure_traits::{One, Zero},
    };

    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;
    #[cfg(feature = "extension_degree_8")]
    use std::num::Wrapping;

    //Checks the hot coefficient shapes used by bivariate evaluation.
    #[test]
    fn test_bivariate_supported_shapes() {
        let two = ResiduePolyF4Z128::ONE + ResiduePolyF4Z128::ONE;
        let bpoly2 = BivariatePoly::from_coeffs(vec![ResiduePolyF4Z128::ONE; 4], 1);
        let expected2 = Poly::from_coefs(vec![two; 2]);
        assert_eq!(
            bpoly2.partial_x_evaluation(ResiduePolyF4Z128::ONE),
            expected2
        );
        assert_eq!(
            bpoly2.partial_y_evaluation(ResiduePolyF4Z128::ONE),
            expected2
        );
        assert_eq!(
            bpoly2.full_evaluation(ResiduePolyF4Z128::ONE, ResiduePolyF4Z128::ONE),
            two + two
        );

        let five = two + two + ResiduePolyF4Z128::ONE;
        let bpoly5 = BivariatePoly::from_coeffs(vec![ResiduePolyF4Z128::ONE; 25], 4);
        let expected5 = Poly::from_coefs(vec![five; 5]);
        assert_eq!(
            bpoly5.partial_x_evaluation(ResiduePolyF4Z128::ONE),
            expected5
        );
        assert_eq!(
            bpoly5.partial_y_evaluation(ResiduePolyF4Z128::ONE),
            expected5
        );
        assert_eq!(
            bpoly5.full_evaluation(ResiduePolyF4Z128::ONE, ResiduePolyF4Z128::ONE),
            five + five + five + five + five
        );
    }

    #[test]
    fn bivariate_partial_evals_match_full() {
        // F(X, Y) = 1 + 2*Y + 3*X + 4*X*Y, stored row-major as [a_00, a_01, a_10, a_11].
        let one = ResiduePolyF4Z128::ONE;
        let two = one + one;
        let three = two + one;
        let four = two + two;
        let five = four + one;
        let seven = four + three;
        let bpoly = BivariatePoly::from_coeffs(vec![one, two, three, four], 1);

        // F(5, Y) = (1 + 3*5) + (2 + 4*5)*Y = 16 + 22*Y
        let sixteen = five + five + five + one;
        let twentytwo = sixteen + three + three;
        assert_eq!(
            bpoly.partial_x_evaluation(five),
            Poly::from_coefs(vec![sixteen, twentytwo])
        );

        // F(X, 5) = (1 + 2*5) + (3 + 4*5)*X = 11 + 23*X
        let eleven = five + five + one;
        let twentythree = eleven + four + four + four;
        assert_eq!(
            bpoly.partial_y_evaluation(five),
            Poly::from_coefs(vec![eleven, twentythree])
        );

        // Fused returns (F(alpha, Y), F(X, alpha)).
        let (px, py) = bpoly.partial_evaluations(five);
        assert_eq!(px, Poly::from_coefs(vec![sixteen, twentytwo]));
        assert_eq!(py, Poly::from_coefs(vec![eleven, twentythree]));

        // F(5, 7) = 1 + 2*7 + 3*5 + 4*5*7 = 170
        let mut expected_full = ResiduePolyF4Z128::ZERO;
        for _ in 0..170 {
            expected_full += one;
        }
        assert_eq!(bpoly.full_evaluation(five, seven), expected_full);
    }

    #[rstest]
    fn test_bivariate_partial_evaluations(#[values(1, 4, 10)] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z128::sample(&mut rng);
        let point = ResiduePolyF4Z128::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree);

        let (partial_x, partial_y) = bpoly.partial_evaluations(point);

        assert_eq!(partial_x, bpoly.partial_x_evaluation(point));
        assert_eq!(partial_y, bpoly.partial_y_evaluation(point));
    }

    //Test that eval at 0 return the secret for ResiduePolyF4Z128
    #[rstest]
    fn test_bivariate_zero_128(#[values(4, 10, 20)] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z128::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree);
        let ev_zero = bpoly.full_evaluation(ResiduePolyF4Z128::ZERO, ResiduePolyF4Z128::ZERO);
        assert_eq!(ev_zero, secret);
    }

    //Test that eval at 0 return the secret for ResiduePolyF4Z64
    #[rstest]
    fn test_bivariate_zero_64(#[values(4, 10, 20)] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z64::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree);
        let ev_zero = bpoly.full_evaluation(ResiduePolyF4Z64::ZERO, ResiduePolyF4Z64::ZERO);
        assert_eq!(ev_zero, secret);
    }

    //Test that eval at 1 return the sum of all coefs of the poly for ResiduePolyF4Z128
    #[rstest]
    fn test_bivariate_one_128(#[values(4, 10, 20)] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z128::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree);
        let ev_one = bpoly.full_evaluation(ResiduePolyF4Z128::ONE, ResiduePolyF4Z128::ONE);
        let sum_coefs = bpoly
            .coeffs()
            .iter()
            .fold(ResiduePoly::ZERO, |acc, x| acc + x);
        assert_eq!(ev_one, sum_coefs);
    }

    //Test that eval at 1 return the sum of all coefs of the poly for ResiduePolyF4Z64
    #[rstest]
    fn test_bivariate_one_64(#[values(4, 10, 20)] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z64::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree);
        let ev_one = bpoly.full_evaluation(ResiduePolyF4Z64::ONE, ResiduePolyF4Z64::ONE);
        let sum_coefs = bpoly
            .coeffs()
            .iter()
            .fold(ResiduePoly::ZERO, |acc, x| acc + x);
        assert_eq!(ev_one, sum_coefs);
    }

    //Setup up a hardcoded polynomial chosen at random with Sage
    #[cfg(feature = "extension_degree_8")]
    fn poly_setup() -> (BivariatePoly<ResiduePolyF8Z128>, ResiduePolyF8Z128) {
        let coefs = vec![
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x0y0
            ResiduePoly {
                coefs: [
                    Wrapping(281355203632430276713284577500636745225_u128),
                    Wrapping(4258970560501905299756142735602571347_u128),
                    Wrapping(41543403022018644758011184019714688351_u128),
                    Wrapping(337138296132871657924201015670262013102_u128),
                    Wrapping(225403464165698745679361729175441873314_u128),
                    Wrapping(235874713983497274551959101520003532755_u128),
                    Wrapping(66887312209425701725638651176375972080_u128),
                    Wrapping(51083761568983112204121355358960196726_u128),
                ],
            }, //x0y1
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x0y2
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x0y3
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x0y4
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x1y0
            ResiduePoly {
                coefs: [
                    Wrapping(260172270899838015168364469307267903604_u128),
                    Wrapping(133709072688942343053642842723049802783_u128),
                    Wrapping(51432298487759450757313535229032839119_u128),
                    Wrapping(65008045700452643894172674756773789738_u128),
                    Wrapping(258016220364701866281559758524652202811_u128),
                    Wrapping(309810794168020863508648007675638087903_u128),
                    Wrapping(296147914607342802049867860229738641508_u128),
                    Wrapping(13457995150159418340564381113310860750_u128),
                ],
            }, //x1y1
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x1y2
            ResiduePoly {
                coefs: [
                    Wrapping(163444429592770747297613457473781641215_u128),
                    Wrapping(228935582172901367934387061083764943853_u128),
                    Wrapping(179800712636635787104661763784656954850_u128),
                    Wrapping(13519225383366564446938113740201783219_u128),
                    Wrapping(73582106883191031116267187464310036349_u128),
                    Wrapping(277461172367649777497529532975853533045_u128),
                    Wrapping(12602500458733663470328110731855050601_u128),
                    Wrapping(325785298567603990538408201152147487273_u128),
                ],
            }, //x1y3
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x1y4
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x2y0
            ResiduePoly {
                coefs: [
                    Wrapping(311993895544877585914601466861963189126_u128),
                    Wrapping(172651756440666489064157315247427271896_u128),
                    Wrapping(204010202379821158158443918685063746651_u128),
                    Wrapping(76628626384302138295374803790481658964_u128),
                    Wrapping(326998774339864122254645920546695911553_u128),
                    Wrapping(52646544085681437246125146014550850772_u128),
                    Wrapping(316927440038237513796466089939508394554_u128),
                    Wrapping(302148183116531569659009633899831166254_u128),
                ],
            }, //x2y1
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x2y2
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x2y3
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x2y4
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x3y0
            ResiduePoly {
                coefs: [
                    Wrapping(286138236564379691751051902318328840025_u128),
                    Wrapping(82938171472760550696234034574003087597_u128),
                    Wrapping(33833911291976164459972092627074322808_u128),
                    Wrapping(116098816107144743036025629794991956882_u128),
                    Wrapping(338167143689363597691743357603482846022_u128),
                    Wrapping(26165133013497791066256472672255319694_u128),
                    Wrapping(18458136718278400956516334586279745132_u128),
                    Wrapping(288777315718711210089865077619101981424_u128),
                ],
            }, //x3y1
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x3y2
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x3y3
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x3y4
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x4y0
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x4y1
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x4y2
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x4y3
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //x4y4
        ];

        let bpoly = BivariatePoly::from_coeffs(coefs, 4);

        let point = ResiduePoly {
            coefs: [
                Wrapping(243062921045605446873380261285612014099_u128),
                Wrapping(233922831823877510168779466170958540719_u128),
                Wrapping(83095764130704444068497224236235151843_u128),
                Wrapping(266191277596221096809987871207939360795_u128),
                Wrapping(188401405184384435680050377285176529756_u128),
                Wrapping(141347310720178979738526094711177072321_u128),
                Wrapping(261999724680859524134713498494747190320_u128),
                Wrapping(30370748131668745141379384486438344404_u128),
            ],
        };

        (bpoly, point)
    }

    //Checking partial eval x of the setup polynomial, checked against Sage
    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_bivariate_partial_eval_x() {
        let (bpoly, point) = poly_setup();
        let res = bpoly.partial_x_evaluation(point);

        let expected_result = Poly::<ResiduePolyF8Z128>::from_coefs(vec![
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(194659304737652150274621743969329712438_u128),
                    Wrapping(115685945677868204172585339280717591321_u128),
                    Wrapping(169699422973071654346792619067607866670_u128),
                    Wrapping(321100274427556339261468557161987205751_u128),
                    Wrapping(195462117064886035019009854572906963164_u128),
                    Wrapping(291339002808732288285336967010694614055_u128),
                    Wrapping(227667236883020811656236216622638022479_u128),
                    Wrapping(111107134209136259497829196880415286861_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(147454880481104232835922501791269260818_u128),
                    Wrapping(65465170413206610326920172544645541174_u128),
                    Wrapping(93236257691904232563708805938564129299_u128),
                    Wrapping(155706651091356865905198284014665420963_u128),
                    Wrapping(191853049678401528554852500058265028133_u128),
                    Wrapping(169352184245891491494444673534070536232_u128),
                    Wrapping(138875474704417926564925414355672698438_u128),
                    Wrapping(62042910943958481560375824830383748680_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            },
        ]);

        assert_eq!(res, expected_result);
    }

    //Checking partial eval y of the setup polynomial, checked against Sage
    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_bivariate_partial_eval_y() {
        //Taking Sage as reference
        let (bpoly, point) = poly_setup();
        let res = bpoly.partial_y_evaluation(point);

        let expected_result = Poly::<ResiduePolyF8Z128>::from_coefs(vec![
            ResiduePoly {
                coefs: [
                    Wrapping(201011427321774599482568837072770222480_u128),
                    Wrapping(11947668628466305484845266609591726489_u128),
                    Wrapping(69450643145791245497886627400193290916_u128),
                    Wrapping(52602571092206009467823484151543166903_u128),
                    Wrapping(224549574104317112479612329539181369785_u128),
                    Wrapping(237188827600534885306506803777179132832_u128),
                    Wrapping(337746828579109619160145562864273140551_u128),
                    Wrapping(194794966634209513665432034913002287282_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(15534540341544077333485629482685556983_u128),
                    Wrapping(102137375687280591904357361381864283910_u128),
                    Wrapping(313193850724129059476368899766085275886_u128),
                    Wrapping(184445872102471941817162671172157093385_u128),
                    Wrapping(145892334667775198680982773891695966711_u128),
                    Wrapping(12035224209516384700884015529761895359_u128),
                    Wrapping(127420874420047592073367830265565440284_u128),
                    Wrapping(83363095314314986646908258467169833274_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(6789996746804626888188836103074992860_u128),
                    Wrapping(224144536684548159123994093745570895575_u128),
                    Wrapping(86263644680843427503974616985670812760_u128),
                    Wrapping(177963489535853129498538648878873325825_u128),
                    Wrapping(44380349963576940170581732126952083169_u128),
                    Wrapping(223903890258473843424549423845416822781_u128),
                    Wrapping(101855678291082912034572954513892058977_u128),
                    Wrapping(103425740087765622108029333800331006686_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(125282582454093692796288940448287589127_u128),
                    Wrapping(156583199810545222234926477955564404552_u128),
                    Wrapping(53976853057841824456213450153642528974_u128),
                    Wrapping(261904549797046130835127155153696559898_u128),
                    Wrapping(191933233286381918543285561179452794417_u128),
                    Wrapping(58025913687275085976380380921341802375_u128),
                    Wrapping(157727573697178459210200091732618328865_u128),
                    Wrapping(79355704402495352443477030202615414328_u128),
                ],
            },
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            },
        ]);
        assert_eq!(res, expected_result);
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_full_eval() {
        let (bpoly, point) = poly_setup();
        let point_x = point;
        let point_y = point_x + point_x;
        let res = bpoly.full_evaluation(point_x, point_y);

        let expected_res = bpoly.partial_x_evaluation(point_x).eval(&point_y);

        assert_eq!(res, expected_res);
    }
}
