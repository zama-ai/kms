use crate::shamir::ShamirSharing;
use aes_prng::AesRng;
use anyhow::anyhow;
use hash_map::HashMap;
use std::collections::hash_map;
use std::str::FromStr;

use crate::parser::Circuit;
use rand::SeedableRng;
use std::ops::{Add, Mul};

fn bit_generation(rng: &mut AesRng) -> ShamirSharing {
    // this can act as a trusted dealer
    ShamirSharing {
        share: rng.get_bit() as u64,
    }
}

struct Memory<'l> {
    sp: HashMap<&'l str, ShamirSharing>,
    ci: HashMap<&'l str, i64>,
    cp: HashMap<&'l str, u64>,
}

impl<'l> Memory<'l> {
    fn new() -> Self {
        Memory {
            sp: HashMap::new(),
            ci: HashMap::new(),
            cp: HashMap::new(),
        }
    }

    fn write_sp(&mut self, reg: &'l str, b: ShamirSharing) {
        self.sp.insert(reg, b);
    }

    fn get_sp(&self, reg: &'l str) -> Option<&ShamirSharing> {
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

fn load_secret(secret: ShamirSharing, mem: &mut Memory) {
    let input_register = "s6";
    mem.write_sp(input_register, secret);
}

// allow clippy to use get(0) instead of first()
#[allow(clippy::get_first)]
pub fn execute_bitdec_circuit(
    secret: ShamirSharing,
    circuit: Circuit,
) -> Result<Vec<u64>, anyhow::Error> {
    let mut mem = Memory::new();
    // initialize memory with secret
    load_secret(secret, &mut mem);

    let seed = AesRng::generate_random_seed();
    let mut rng = AesRng::from_seed(seed);
    let mut outputs = Vec::new();

    for op in circuit.operations {
        use crate::parser::Operator::*;
        match op.operator {
            AddCI => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let ci = u64::from_str(op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?)?;

                let c1 = mem
                    .get_cp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;
                mem.write_cp(out_register, c1 + ci);
            }
            AddM => {
                let r0 = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let r2 = op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?;

                let s = mem
                    .get_sp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;
                let c = *mem
                    .get_cp(r2)
                    .ok_or(anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(r0, s.add(c));
            }
            AddS => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let r2 = op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?;

                let s1 = mem
                    .get_sp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;
                let s2 = mem
                    .get_sp(r2)
                    .ok_or(anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(out_register, s1.add(s2));
            }
            Bit => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let b = bit_generation(&mut rng);
                mem.write_sp(out_register, b);
            }
            BitDecInt => {
                let n_regs = usize::from_str(
                    op.operands
                        .get(0)
                        .ok_or(anyhow!("Wrong index in BitDecInt"))?,
                )?;

                let r0 = *op
                    .operands
                    .get(1)
                    .ok_or(anyhow!("Wrong index 1 in BitDecInt"))?;
                let source = *mem
                    .get_ci(r0)
                    .ok_or(anyhow!("Couldn't find register {r0}"))?;

                for i in 0..n_regs - 1 {
                    let index = i + 2;
                    let dest = *op
                        .operands
                        .get(index)
                        .ok_or(anyhow!("Wrong index buddy, got {index}"))?;
                    mem.write_ci(dest, (source >> i) & 1);
                }
            }
            ConvInt => {
                let dest = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let source = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let ci = *mem
                    .get_ci(source)
                    .ok_or(anyhow!("Couldn't find register {source}"))?;
                mem.write_cp(dest, ci as u64);
            }
            ConvModp => {
                let r0 = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let bit_length =
                    usize::from_str(op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?)?;

                let cp1 = *mem
                    .get_cp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;

                if bit_length == 0 {
                    mem.write_ci(r0, cp1 as i64);
                } else {
                    todo!()
                }
            }
            LdI => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let to_load =
                    u64::from_str(op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?)?;
                mem.write_cp(out_register, to_load);
            }
            LdSI => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let to_load =
                    u64::from_str(op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?)?;
                mem.write_sp(out_register, ShamirSharing { share: to_load });
            }
            MulM => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let r2 = op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?;

                let s1 = mem
                    .get_sp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;
                let c = mem
                    .get_cp(r2)
                    .ok_or(anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(out_register, s1.mul(*c));
            }
            MulCI => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let ci = u64::from_str(op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?)?;

                let c1 = mem
                    .get_cp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;
                mem.write_cp(out_register, c1 * ci);
            }
            MulS => {
                let n_regs =
                    usize::from_str(op.operands.get(0).ok_or(anyhow!("Wrong index in MulS"))?)?;

                for i in 0..n_regs / 3 {
                    let r0 = *op
                        .operands
                        .get(3 * i + 1)
                        .ok_or(anyhow!("Wrong index r0: {} in MulS", 3 * i + 1))?;
                    let r1 = *op
                        .operands
                        .get(3 * i + 2)
                        .ok_or(anyhow!("Wrong index r1: {} in MulS", 3 * i + 2))?;
                    let r2 = *op
                        .operands
                        .get(3 * i + 3)
                        .ok_or(anyhow!("Wrong index r2: {} in MulS", 3 * i + 3))?;

                    let s1 = mem
                        .get_sp(r1)
                        .ok_or(anyhow!("Couldn't find register {r1}"))?;

                    let s2 = mem
                        .get_sp(r2)
                        .ok_or(anyhow!("Couldn't find register {r2}"))?;

                    mem.write_sp(r0, s1.mul(s2));
                }
            }
            MulSI => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let s1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let ci = u64::from_str(op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?)?;

                let s1 = mem
                    .get_sp(s1)
                    .ok_or(anyhow!("Couldn't find register {s1}"))?;
                mem.write_sp(out_register, s1.mul(ci));
            }
            Open => {
                let n_regs =
                    usize::from_str(op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?)?;
                let _check = bool::from_str(
                    &op.operands
                        .get(1)
                        .ok_or(anyhow!("Wrong index buddy"))?
                        .to_lowercase(),
                )?;

                for i in 1..(n_regs + 1) / 2 {
                    let r0 = op.operands.get(2 * i).ok_or(anyhow!("Wrong index buddy"))?;
                    let r1 = *op
                        .operands
                        .get(2 * i + 1)
                        .ok_or(anyhow!("Wrong index buddy"))?;

                    let s = mem
                        .get_sp(r1)
                        .ok_or(anyhow!("Couldn't find register {r1}"))?;

                    mem.write_cp(r0, s.reveal());
                }
            }
            SubS => {
                let out_register = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let r2 = op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?;

                let s1 = mem
                    .get_sp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;
                let s2 = mem
                    .get_sp(r2)
                    .ok_or(anyhow!("Couldn't find register {r2}"))?;

                mem.write_sp(out_register, s1 - s2);
            }
            ShrCI => {
                let r0 = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let r1 = op.operands.get(1).ok_or(anyhow!("Wrong index buddy"))?;
                let ci = usize::from_str(op.operands.get(2).ok_or(anyhow!("Wrong index buddy"))?)?;

                let c1 = mem
                    .get_cp(r1)
                    .ok_or(anyhow!("Couldn't find register {r1}"))?;

                mem.write_cp(r0, c1 << ci);
            }
            PrintRegPlain => {
                let r0 = op.operands.get(0).ok_or(anyhow!("Wrong index buddy"))?;
                let c = mem
                    .get_cp(r0)
                    .ok_or(anyhow!("Couldn't find register {r0}"))?;
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
    use rstest::rstest;

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
    fn test_execution(#[case] x: u64, #[case] expected: Vec<u64>) {
        let circuit = Circuit::try_from(crate::parser::BIT_DEC_CIRCUIT).unwrap();
        let shared_x = ShamirSharing { share: x };
        let v = execute_bitdec_circuit(shared_x, circuit.clone()).unwrap();
        assert_eq!(v, expected);
    }
}
