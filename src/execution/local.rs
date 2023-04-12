use super::Session;
use crate::{Sharing, Z64};
use rand::RngCore;
use std::{num::Wrapping, ops::Mul};

/// Local session without network interaction
pub struct LocalSession<T, R: rand::RngCore> {
    secret: T,
    num_parties: usize,
    threshold: usize,
    rng: R,
}

impl<T, R> Session<T, R> for LocalSession<T, R>
where
    for<'l> &'l T: Mul<&'l T, Output = T>,
    T: Sharing + Clone,
    R: rand::RngCore,
{
    /// TODO this currently reconstructs and does a plain-text multiplication
    fn mul(&mut self, x: &T, y: &T) -> T {
        let xp = x.reveal(self.threshold);
        let yp = y.reveal(self.threshold);

        T::share(&mut self.rng, xp * yp, self.num_parties, self.threshold)
    }

    fn secret(&self) -> T {
        self.secret.clone()
    }

    fn reveal(&self, share: &T) -> Wrapping<u64> {
        share.reveal(self.threshold)
    }

    fn bit_generation(&mut self) -> T {
        let bit = self.rng.next_u64() % 2;
        T::share(
            &mut self.rng,
            Wrapping(bit),
            self.num_parties,
            self.threshold,
        )
    }
}

impl Sharing for Z64 {
    fn reveal(&self, _threshold: usize) -> Wrapping<u64> {
        *self
    }

    fn share<R: RngCore>(
        _rng: &mut R,
        secret: Self,
        _num_parties: usize,
        _threshold: usize,
    ) -> Self {
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::execute_circuit;
    use crate::{Z128, Z64};
    use paste::paste;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rstest::rstest;

    macro_rules! exection_test {
        ($z:ty) => {
            paste! {
                #[rstest]
            #[case(
                10,
                vec![0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            )]
            #[case(
                32132198412,
                vec![0,0,1,1,0,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            )]
            #[case(
                18446744073709551615,
                vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            )]
            #[case(
                0,
                vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            )]
            fn [<test_execution_ $z:lower>](#[case] x: u64, #[case] expected: Vec<u64>) {
                let mut rng = ChaCha12Rng::seed_from_u64(234);
                let shamir_sharings =
                    crate::shamir::ShamirGSharings::<$z>::share(&mut rng, Wrapping(x.into()), 9, 5).unwrap();

                let sess = LocalSession {
                    secret: shamir_sharings,
                    num_parties: 9,
                    threshold: 5,
                    rng: ChaCha12Rng::seed_from_u64(100),
                };

                let v = execute_circuit(sess, &crate::circuit::BIT_DEC_CIRCUIT).unwrap();
                assert_eq!(v, expected.iter().map(|x| Wrapping(*x)).collect::<Vec<_>>());

                // let single_u64_share = Ring64 { value: x };
                let single_u64_share = Wrapping(x);

                let sess = LocalSession {
                    secret: single_u64_share,
                    num_parties: 9,
                    threshold: 5,
                    rng: ChaCha12Rng::seed_from_u64(200),
                };

                let v = execute_circuit(sess, &crate::circuit::BIT_DEC_CIRCUIT).unwrap();
                assert_eq!(v, expected.iter().map(|x| Wrapping(*x)).collect::<Vec<_>>());
            }
            }
        };
    }

    exection_test!(Z128);
    exection_test!(Z64);
}
