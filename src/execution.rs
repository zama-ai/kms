use crate::parser::Circuit;
use crate::poly_shamir::{Sharing, Z64};
use anyhow::anyhow;
use derive_more::Display;
use hash_map::HashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::hash_map;
use std::num::Wrapping;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

/// Runtime identity of player.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Display, Serialize, Deserialize)]
pub struct Identity(pub u64);

impl From<u64> for Identity {
    fn from(s: u64) -> Self {
        Identity(s)
    }
}

pub struct Memory<'l, T> {
    sp: HashMap<&'l str, T>,
    ci: HashMap<&'l str, i64>,
    cp: HashMap<&'l str, u64>,
}

impl<'l, T> Memory<'l, T> {
    fn new() -> Self {
        Memory {
            sp: HashMap::new(),
            ci: HashMap::new(),
            cp: HashMap::new(),
        }
    }

    fn write_sp(&mut self, reg: &'l str, b: T) {
        self.sp.insert(reg, b);
    }

    fn get_sp(&self, reg: &'l str) -> Option<&T> {
        self.sp.get(reg)
    }

    fn write_cp(&mut self, reg: &'l str, val: u64) {
        self.cp.insert(reg, val);
    }

    fn get_cp(&self, reg: &'l str) -> Option<&u64> {
        self.cp.get(reg)
    }

    fn write_ci(&mut self, reg: &'l str, val: i64) {
        self.ci.insert(reg, val);
    }

    fn get_ci(&self, reg: &'l str) -> Option<&i64> {
        self.ci.get(reg)
    }
}

pub trait Session<T, R: rand::RngCore> {
    fn mul(&mut self, x: &T, y: &T) -> T;
    fn reveal(&self, share: &T) -> Z64;
    fn bit_generation(&mut self) -> T;
    fn initialize_mem_with_secret(&self, mem: &mut Memory<T>);
}

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

    fn initialize_mem_with_secret(&self, mem: &mut Memory<T>) {
        let input_register = "s6";
        mem.write_sp(input_register, self.secret.clone());
    }

    fn reveal(&self, share: &T) -> Z64 {
        Wrapping(share.reveal(self.threshold))
    }

    fn bit_generation(&mut self) -> T {
        let bit = self.rng.next_u64() % 2;
        T::share(&mut self.rng, bit, self.num_parties, self.threshold)
    }
}

#[allow(dead_code)] // TODO remove
struct DistributedSession {
    // TODO add networking functions here
}

pub fn execute_circuit<T, S, R>(mut session: S, circuit: &Circuit) -> anyhow::Result<Vec<u64>>
where
    S: Session<T, R>,
    T: Clone,
    R: RngCore,
    for<'l> &'l T: Add<&'l T, Output = T>,
    for<'l> &'l T: Sub<&'l T, Output = T>,
    for<'l> &'l T: Add<u64, Output = T>,
    for<'l> &'l T: Mul<u64, Output = T>,
{
    let mut mem: Memory<T> = Memory::new();

    // initialize memory with secret
    session.initialize_mem_with_secret(&mut mem);

    let mut outputs = Vec::new();

    #[allow(clippy::get_first)]
    for op in &circuit.operations {
        use crate::parser::Operator::*;
        match op.operator {
            AddCI => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let ci = u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;

                let c1 = mem
                    .get_cp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;
                mem.write_cp(out_register, c1 + ci);
            }
            AddM => {
                let r0 = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r2 = op
                    .operands
                    .get(2)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let s = mem
                    .get_sp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;
                let c = *mem
                    .get_cp(r2)
                    .ok_or_else(|| anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(r0, s + c);
            }
            AddS => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r2 = op
                    .operands
                    .get(2)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let s1 = mem
                    .get_sp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;
                let s2 = mem
                    .get_sp(r2)
                    .ok_or_else(|| anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(out_register, s1 + s2);
            }
            Bit => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let b = session.bit_generation();
                mem.write_sp(out_register, b);
            }
            BitDecInt => {
                let n_regs = usize::from_str(
                    op.operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index in BitDecInt"))?,
                )?;

                let r0 = *op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index 1 in BitDecInt"))?;
                let source = *mem
                    .get_ci(r0)
                    .ok_or_else(|| anyhow!("Couldn't find register {r0}"))?;

                for i in 0..n_regs - 1 {
                    let index = i + 2;
                    let dest = *op
                        .operands
                        .get(index)
                        .ok_or_else(|| anyhow!("Wrong index buddy, got {index}"))?;
                    mem.write_ci(dest, (source >> i) & 1);
                }
            }
            ConvInt => {
                let dest = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let source = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let ci = *mem
                    .get_ci(source)
                    .ok_or_else(|| anyhow!("Couldn't find register {source}"))?;
                mem.write_cp(dest, ci as u64);
            }
            ConvModp => {
                let r0 = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let bit_length = usize::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;

                let cp1 = *mem
                    .get_cp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;

                if bit_length == 0 {
                    mem.write_ci(r0, cp1 as i64);
                } else {
                    todo!()
                }
            }
            LdI => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let to_load = u64::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;
                mem.write_cp(out_register, to_load);
            }
            LdSI => {
                // let out_register = op.operands.get(0).ok_or_else(|| anyhow!("Wrong index buddy"))?;
                // let to_load =
                //     u64::from_str(op.operands.get(1).ok_or_else(|| anyhow!("Wrong index buddy"))?)?;
                // mem.write_sp(out_register, ShamirU64Sharing { share: to_load });
                todo!();
            }
            MulM => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r2 = op
                    .operands
                    .get(2)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let s1 = mem
                    .get_sp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;
                let c = mem
                    .get_cp(r2)
                    .ok_or_else(|| anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(out_register, s1 * *c);
            }
            MulCI => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let ci = u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;

                let c1 = mem
                    .get_cp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;
                mem.write_cp(out_register, c1 * ci);
            }
            MulS => {
                let n_regs = usize::from_str(
                    op.operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index in MulS"))?,
                )?;

                for i in 0..n_regs / 3 {
                    let r0 = *op
                        .operands
                        .get(3 * i + 1)
                        .ok_or_else(|| anyhow!("Wrong index r0: {} in MulS", 3 * i + 1))?;
                    let r1 = *op
                        .operands
                        .get(3 * i + 2)
                        .ok_or_else(|| anyhow!("Wrong index r1: {} in MulS", 3 * i + 2))?;
                    let r2 = *op
                        .operands
                        .get(3 * i + 3)
                        .ok_or_else(|| anyhow!("Wrong index r2: {} in MulS", 3 * i + 3))?;

                    let s1 = mem
                        .get_sp(r1)
                        .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;

                    let s2 = mem
                        .get_sp(r2)
                        .ok_or_else(|| anyhow!("Couldn't find register {r2}"))?;

                    // temporary call before actual mul is implemented. Needs sharing parameters for now.
                    mem.write_sp(r0, session.mul(s1, s2));
                }
            }
            MulSI => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let s1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let ci = u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;

                let s1 = mem
                    .get_sp(s1)
                    .ok_or_else(|| anyhow!("Couldn't find register {s1}"))?;
                mem.write_sp(out_register, s1 * ci);
            }
            Open => {
                let n_regs = usize::from_str(
                    op.operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;
                let _check = bool::from_str(
                    &op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?
                        .to_lowercase(),
                )?;

                for i in 1..(n_regs + 1) / 2 {
                    let r0 = op
                        .operands
                        .get(2 * i)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                    let r1 = *op
                        .operands
                        .get(2 * i + 1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let s = mem
                        .get_sp(r1)
                        .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;

                    mem.write_cp(r0, session.reveal(s).0);
                }
            }
            SubS => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r2 = op
                    .operands
                    .get(2)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let s1 = mem
                    .get_sp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;
                let s2 = mem
                    .get_sp(r2)
                    .ok_or_else(|| anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(out_register, s1 - s2);
            }
            ShrCI => {
                let r0 = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let r1 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let ci = usize::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;

                let c1 = mem
                    .get_cp(r1)
                    .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;

                mem.write_cp(r0, c1 << ci);
            }
            PrintRegPlain => {
                let r0 = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let c = mem
                    .get_cp(r0)
                    .ok_or_else(|| anyhow!("Couldn't find register {r0}"))?;
                // print!("{:?}", c);
                // convert prints to outputs for testing purposes
                outputs.push(*c);
            }
        }
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly_shamir::Z128;
    use crate::ring64::Ring64;
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
                let circuit = Circuit::try_from(crate::parser::BIT_DEC_CIRCUIT).unwrap();
                let mut rng = ChaCha12Rng::seed_from_u64(234);
                let shamir_sharings =
                    crate::poly_shamir::ZPoly::<$z>::share(&mut rng, Wrapping(x.into()), 9, 5).unwrap();

                let sess = LocalSession {
                    secret: shamir_sharings,
                    num_parties: 9,
                    threshold: 5,
                    rng: ChaCha12Rng::seed_from_u64(100),
                };

                let v = execute_circuit(sess, &circuit).unwrap();
                assert_eq!(v, expected);

                let single_u64_share = Ring64 { value: x };

                let sess = LocalSession {
                    secret: single_u64_share,
                    num_parties: 9,
                    threshold: 5,
                    rng: ChaCha12Rng::seed_from_u64(200),
                };

                let v = execute_circuit(sess, &circuit).unwrap();
                assert_eq!(v, expected);
            }
            }
        };
    }

    exection_test!(Z128);
    exection_test!(Z64);
}
