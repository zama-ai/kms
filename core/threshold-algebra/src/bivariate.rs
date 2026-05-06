use super::poly::Poly;
use super::structure_traits::One;
use super::structure_traits::Ring;
use super::structure_traits::Sample;
use super::structure_traits::Zero;

use anyhow::Result;
use rand::{CryptoRng, Rng};
use std::ops::Mul;

/// Bivariate polynomial is a row-major matrix of coefficients of ResiduePolynomials
/// The row view of the polynomials is the following:
/// [[a_{00}, a_{01}, ..., a_{0d}], ..., [a_{d0}, ..., a_{dd}]]
#[derive(Clone, Default, Debug)]
pub struct BivariatePoly<Z> {
    pub coefs: Vec<Z>,
    degree: usize,
}

impl<Z> BivariatePoly<Z> {
    /// method for sampling random bivariate polynomial where free term is the secret
    pub fn from_secret<R: Rng + CryptoRng>(rng: &mut R, secret: Z, degree: usize) -> Result<Self>
    where
        Z: Sample + Zero + Copy,
    {
        let d = degree + 1;
        let n = d * d;
        let mut coefs = Vec::with_capacity(n);
        coefs.push(secret);
        coefs.extend((1..n).map(|_| Z::sample(rng)));

        Ok(BivariatePoly { coefs, degree })
    }
}

/// computes powers of a list of points in F up to a given maximal exponent
pub fn compute_powers_list<F: One + Mul<Output = F> + Copy>(
    points: &[F],
    max_exponent: usize,
) -> Vec<Vec<F>> {
    let mut alpha_powers = Vec::new();
    for p in points {
        alpha_powers.push(compute_powers(*p, max_exponent));
    }
    alpha_powers
}

/// Computes powers of a specific point up to degree: p^0, p^1,...,p^degree
pub fn compute_powers<Z: One + Mul<Output = Z> + Copy>(point: Z, degree: usize) -> Vec<Z> {
    let mut powers_of_point = Vec::new();
    powers_of_point.push(Z::ONE); // start with
    for i in 1..=degree {
        powers_of_point.push(powers_of_point[i - 1] * point);
    }
    powers_of_point
}

macro_rules! eval_row_y {
    ($coefs:expr, $start:expr, $alpha:expr, $last:expr $(, $idx:expr)+) => {{
        let mut acc = $coefs[$start + $last];
        $(acc = acc * $alpha + $coefs[$start + $idx];)+
        acc
    }};
}

macro_rules! eval_col_x {
    ($coefs:expr, $col:expr, $d:expr, $alpha:expr, $last:expr $(, $idx:expr)+) => {{
        let mut acc = $alpha * $coefs[$last * $d + $col];
        $(acc = $alpha * ($coefs[$idx * $d + $col] + acc);)+
        $coefs[$col] + acc
    }};
}

impl<Z> BivariatePoly<Z> {
    fn dimension(&self) -> usize {
        self.degree + 1
    }
}

pub trait BivariateEval<Z: Ring> {
    /// Given a degree T bivariate poly F(X,Y) and a point \alpha, we compute
    /// G(X) = F(X, \alpha) as
    /// [sum(alpha^j * a_{j0}), ..., sum(alpha^j * a_{jd})]
    fn partial_x_evaluation(&self, alpha: Z) -> Result<Poly<Z>>;

    /// Given a degree T bivariate poly F(X,Y) and a point \alpha, we compute
    /// G(Y) := F(\alpha, Y) as
    /// [sum(alpha^j * a_{0j}), ..., sum(alpha^j * a_{dj})]
    fn partial_y_evaluation(&self, alpha: Z) -> Result<Poly<Z>>;

    /// Given a degree T bivariate poly F(X,Y) and two points \alpha_x, \alpha_y, we compute
    /// F(\alpha_x, \alpha_y)
    fn full_evaluation(&self, alpha_x: Z, alpha_y: Z) -> Result<Z>;
}

impl<Z: Ring> BivariateEval<Z> for BivariatePoly<Z> {
    fn partial_x_evaluation(&self, alpha: Z) -> Result<Poly<Z>> {
        let d = self.dimension();
        let coefs = self.coefs.as_slice();
        let res = match d {
            2 => vec![coefs[0] + alpha * coefs[2], coefs[1] + alpha * coefs[3]],
            5 => vec![
                eval_col_x!(coefs, 0, d, alpha, 4, 3, 2, 1),
                eval_col_x!(coefs, 1, d, alpha, 4, 3, 2, 1),
                eval_col_x!(coefs, 2, d, alpha, 4, 3, 2, 1),
                eval_col_x!(coefs, 3, d, alpha, 4, 3, 2, 1),
                eval_col_x!(coefs, 4, d, alpha, 4, 3, 2, 1),
            ],
            _ => {
                let mut res = vec![Z::ZERO; d];
                let mut alpha_power = Z::ONE;
                for row_idx in 0..d {
                    let row_start = row_idx * d;
                    for col_idx in 0..d {
                        res[col_idx] += alpha_power * coefs[row_start + col_idx];
                    }
                    alpha_power *= alpha;
                }
                res
            }
        };
        Ok(Poly::from_coefs(res))
    }

    fn partial_y_evaluation(&self, alpha: Z) -> Result<Poly<Z>> {
        let d = self.dimension();
        let coefs = self.coefs.as_slice();
        let res = match d {
            2 => vec![
                eval_row_y!(coefs, 0, alpha, 1, 0),
                eval_row_y!(coefs, 2, alpha, 1, 0),
            ],
            5 => vec![
                eval_row_y!(coefs, 0, alpha, 4, 3, 2, 1, 0),
                eval_row_y!(coefs, 5, alpha, 4, 3, 2, 1, 0),
                eval_row_y!(coefs, 10, alpha, 4, 3, 2, 1, 0),
                eval_row_y!(coefs, 15, alpha, 4, 3, 2, 1, 0),
                eval_row_y!(coefs, 20, alpha, 4, 3, 2, 1, 0),
            ],
            _ => {
                let mut res = Vec::with_capacity(d);
                for row_idx in 0..d {
                    let row_start = row_idx * d;
                    let mut acc = coefs[row_start + d - 1];
                    for col_idx in (0..d - 1).rev() {
                        acc = acc * alpha + coefs[row_start + col_idx];
                    }
                    res.push(acc);
                }
                res
            }
        };
        Ok(Poly::from_coefs(res))
    }

    fn full_evaluation(&self, alpha_x: Z, alpha_y: Z) -> Result<Z> {
        let d = self.dimension();
        let coefs = self.coefs.as_slice();
        Ok(match d {
            2 => {
                let row0 = eval_row_y!(coefs, 0, alpha_y, 1, 0);
                let row1 = eval_row_y!(coefs, 2, alpha_y, 1, 0);
                row0 + alpha_x * row1
            }
            5 => {
                let row0 = eval_row_y!(coefs, 0, alpha_y, 4, 3, 2, 1, 0);
                let row1 = eval_row_y!(coefs, 5, alpha_y, 4, 3, 2, 1, 0);
                let row2 = eval_row_y!(coefs, 10, alpha_y, 4, 3, 2, 1, 0);
                let row3 = eval_row_y!(coefs, 15, alpha_y, 4, 3, 2, 1, 0);
                let row4 = eval_row_y!(coefs, 20, alpha_y, 4, 3, 2, 1, 0);
                let alpha_x2 = alpha_x * alpha_x;
                let alpha_x3 = alpha_x2 * alpha_x;
                let alpha_x4 = alpha_x3 * alpha_x;
                row0 + alpha_x * row1 + alpha_x2 * row2 + alpha_x3 * row3 + alpha_x4 * row4
            }
            _ => {
                let mut acc = Z::ZERO;
                let mut alpha_x_power = Z::ONE;
                for row_idx in 0..d {
                    let row_start = row_idx * d;
                    let mut row_acc = coefs[row_start + d - 1];
                    for col_idx in (0..d - 1).rev() {
                        row_acc = row_acc * alpha_y + coefs[row_start + col_idx];
                    }
                    acc += alpha_x_power * row_acc;
                    alpha_x_power *= alpha_x;
                }
                acc
            }
        })
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
        structure_traits::One,
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
        let bpoly2 = BivariatePoly {
            coefs: vec![ResiduePolyF4Z128::ONE; 4],
            degree: 1,
        };
        let expected2 = Poly::from_coefs(vec![two; 2]);
        assert_eq!(
            bpoly2.partial_x_evaluation(ResiduePolyF4Z128::ONE).unwrap(),
            expected2
        );
        assert_eq!(
            bpoly2.partial_y_evaluation(ResiduePolyF4Z128::ONE).unwrap(),
            expected2
        );
        assert_eq!(
            bpoly2
                .full_evaluation(ResiduePolyF4Z128::ONE, ResiduePolyF4Z128::ONE)
                .unwrap(),
            two + two
        );

        let five = two + two + ResiduePolyF4Z128::ONE;
        let bpoly5 = BivariatePoly {
            coefs: vec![ResiduePolyF4Z128::ONE; 25],
            degree: 4,
        };
        let expected5 = Poly::from_coefs(vec![five; 5]);
        assert_eq!(
            bpoly5.partial_x_evaluation(ResiduePolyF4Z128::ONE).unwrap(),
            expected5
        );
        assert_eq!(
            bpoly5.partial_y_evaluation(ResiduePolyF4Z128::ONE).unwrap(),
            expected5
        );
        assert_eq!(
            bpoly5
                .full_evaluation(ResiduePolyF4Z128::ONE, ResiduePolyF4Z128::ONE)
                .unwrap(),
            five + five + five + five + five
        );
    }

    //Test that eval at 0 return the secret for ResiduePolyF4Z128
    #[rstest]
    #[case(4)]
    #[case(10)]
    #[case(20)]
    fn test_bivariate_zero_128(#[case] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z128::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree).unwrap();
        let ev_zero = bpoly
            .full_evaluation(ResiduePolyF4Z128::ZERO, ResiduePolyF4Z128::ZERO)
            .unwrap();
        assert_eq!(ev_zero, secret);
    }

    //Test that eval at 0 return the secret for ResiduePolyF4Z64
    #[rstest]
    #[case(4)]
    #[case(10)]
    #[case(20)]
    fn test_bivariate_zero_64(#[case] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z64::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree).unwrap();
        let ev_zero = bpoly
            .full_evaluation(ResiduePolyF4Z64::ZERO, ResiduePolyF4Z64::ZERO)
            .unwrap();
        assert_eq!(ev_zero, secret);
    }

    //Test that eval at 1 return the sum of all coefs of the poly for ResiduePolyF4Z128
    #[rstest]
    #[case(4)]
    #[case(10)]
    #[case(20)]
    fn test_bivariate_one_128(#[case] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z128::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree).unwrap();
        let ev_one = bpoly
            .full_evaluation(ResiduePolyF4Z128::ONE, ResiduePolyF4Z128::ONE)
            .unwrap();
        let sum_coefs = bpoly.coefs.iter().fold(ResiduePoly::ZERO, |acc, x| acc + x);
        assert_eq!(ev_one, sum_coefs);
    }

    //Test that eval at 1 return the sum of all coefs of the poly for ResiduePolyF4Z64
    #[rstest]
    #[case(4)]
    #[case(10)]
    #[case(20)]
    fn test_bivariate_one_64(#[case] degree: usize) {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePolyF4Z64::sample(&mut rng);
        let bpoly = BivariatePoly::from_secret(&mut rng, secret, degree).unwrap();
        let ev_one = bpoly
            .full_evaluation(ResiduePolyF4Z64::ONE, ResiduePolyF4Z64::ONE)
            .unwrap();
        let sum_coefs = bpoly.coefs.iter().fold(ResiduePoly::ZERO, |acc, x| acc + x);
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

        let bpoly = BivariatePoly { coefs, degree: 4 };

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
        let res = bpoly.partial_x_evaluation(point).unwrap();

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
        let res = bpoly.partial_y_evaluation(point).unwrap();

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
        let res = bpoly.full_evaluation(point_x, point_y).unwrap();

        let expected_res = bpoly.partial_x_evaluation(point_x).unwrap().eval(&point_y);

        assert_eq!(res, expected_res);
    }
}
