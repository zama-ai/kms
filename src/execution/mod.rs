use crate::circuit::{Circuit, Operator};
use anyhow::anyhow;
use hash_map::HashMap;
use rand::RngCore;
use std::collections::hash_map;
use std::num::Wrapping;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

pub mod distributed;
pub mod local;
pub mod player;
pub mod prep;
pub mod prss;

/// log_2 of parameter Bd, computed from values in the paper
const LOG_BD: u64 = 72;

/// parameter pow, taken from the paper
const POW: u64 = 47;

/// log_2 of nominator of Bd1
const LOG_BD1_NOM: u32 = (((1_u128 << POW) - 1) * (1_u128 << LOG_BD)).ilog2();

pub struct Memory<'l, T> {
    sp: HashMap<&'l str, T>,
    ci: HashMap<&'l str, Wrapping<i64>>,
    cp: HashMap<&'l str, Wrapping<u64>>,
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

    fn write_cp(&mut self, reg: &'l str, val: Wrapping<u64>) {
        self.cp.insert(reg, val);
    }

    fn get_cp(&self, reg: &'l str) -> Option<&Wrapping<u64>> {
        self.cp.get(reg)
    }

    fn write_ci(&mut self, reg: &'l str, val: Wrapping<i64>) {
        self.ci.insert(reg, val);
    }

    fn get_ci(&self, reg: &'l str) -> Option<&Wrapping<i64>> {
        self.ci.get(reg)
    }
}

pub trait Session<T, R: rand::RngCore> {
    fn mul(&mut self, x: &T, y: &T) -> T;
    fn reveal(&self, share: &T) -> Wrapping<u64>;
    fn bit_generation(&mut self) -> T;
    fn secret(&self) -> T;
}

pub fn execute_circuit<T, S, R>(
    mut session: S,
    circuit: &Circuit,
) -> anyhow::Result<Vec<Wrapping<u64>>>
where
    S: Session<T, R>,
    T: Clone,
    R: RngCore,
    for<'l> &'l T: Add<&'l T, Output = T>,
    for<'l> &'l T: Sub<&'l T, Output = T>,
    for<'l> &'l T: Add<Wrapping<u64>, Output = T>,
    for<'l> &'l T: Mul<Wrapping<u64>, Output = T>,
{
    let mut mem: Memory<T> = Memory::new();

    // initialize memory with secret
    if circuit.input_wires.len() == 1 {
        mem.write_sp(circuit.input_wires[0].as_str(), session.secret());
    } else {
        return Err(anyhow!("Circuit did not contain secret input wire"));
    }

    let mut outputs = Vec::new();

    #[allow(clippy::get_first)]
    for op in &circuit.operations {
        use Operator::*;
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
                let ci = Wrapping(u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?);

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

                let r0 = op
                    .operands
                    .get(1)
                    .ok_or_else(|| anyhow!("Wrong index 1 in BitDecInt"))?;
                let source = *mem
                    .get_ci(r0.as_str())
                    .ok_or_else(|| anyhow!("Couldn't find register {r0}"))?;

                for i in 0..n_regs - 1 {
                    let index = i + 2;
                    let dest = op
                        .operands
                        .get(index)
                        .ok_or_else(|| anyhow!("Wrong index buddy, got {index}"))?;
                    mem.write_ci(dest.as_str(), Wrapping((source.0 >> i) & 1));
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
                mem.write_cp(dest, Wrapping(ci.0 as u64));
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
                    mem.write_ci(r0, Wrapping(cp1.0 as i64));
                } else {
                    todo!()
                }
            }
            LdI => {
                let out_register = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let to_load = Wrapping(u64::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?);
                mem.write_cp(out_register, to_load);
            }
            LdSI => {
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
                let ci = Wrapping(u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?);

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
                    let r0 = op
                        .operands
                        .get(3 * i + 1)
                        .ok_or_else(|| anyhow!("Wrong index r0: {} in MulS", 3 * i + 1))?;
                    let r1 = op
                        .operands
                        .get(3 * i + 2)
                        .ok_or_else(|| anyhow!("Wrong index r1: {} in MulS", 3 * i + 2))?;
                    let r2 = op
                        .operands
                        .get(3 * i + 3)
                        .ok_or_else(|| anyhow!("Wrong index r2: {} in MulS", 3 * i + 3))?;

                    let s1 = mem
                        .get_sp(r1.as_str())
                        .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;

                    let s2 = mem
                        .get_sp(r2.as_str())
                        .ok_or_else(|| anyhow!("Couldn't find register {r2}"))?;

                    // temporary call before actual mul is implemented. Needs sharing parameters for now.
                    mem.write_sp(r0.as_str(), session.mul(s1, s2));
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
                let ci = Wrapping(u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?);

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
                    let r1 = op
                        .operands
                        .get(2 * i + 1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let s = mem
                        .get_sp(r1.as_str())
                        .ok_or_else(|| anyhow!("Couldn't find register {r1}"))?;

                    mem.write_cp(r0, session.reveal(s));
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
            _ => unimplemented!(),
        }
    }
    Ok(outputs)
}
