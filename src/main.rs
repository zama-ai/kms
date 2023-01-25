use crate::hash_map::HashMap;
use anyhow::anyhow;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::alphanumeric1;
use nom::character::complete::{newline, space0, space1, u64};
use nom::combinator::map_res;

use nom::combinator::{all_consuming, value};
use nom::multi::{length_count, many0, many_m_n, separated_list0};
use nom::sequence::pair;
use nom::sequence::{delimited, terminated, tuple};
use std::any;
use std::collections::hash_map;
use std::convert::TryFrom;

const BIT_DEC_CIRCUIT: &[u8] = include_bytes!("mp_spdz/10-bitdec.txt");

type Res<T, U> = nom::IResult<T, U, nom::error::Error<T>>;

#[derive(Debug)]
#[allow(dead_code)] // Not all the fields are used by our code, but we still want to have access to them.
pub(crate) struct Circuit<'l> {
    operations: Vec<Operation<'l>>,
}

#[derive(Debug)]
pub(crate) struct Operation<'l> {
    operator: Operator,
    operands: Vec<&'l str>,
}

pub type Register = usize;

#[derive(Clone, Debug)]
pub(crate) enum Operator {
    AddCI,
    AddS,
    AddM,
    Bit,
    BitDecInt,
    ConvModp,
    ConvInt,
    LdI,
    LdSI,
    MulSI,
    MulS,
    MulCI,
    MulM,
    Open,
    PrintRegPlain,
    SubS,
    ShrCI,
}

fn parse_circuit(bytes: &[u8]) -> Res<&[u8], Circuit> {
    let (bytes, _) = many0(pair(parse_comment, newline))(bytes)?;
    let (bytes, operations) = separated_list0(newline, parse_operation)(bytes)?;
    let (bytes, _) = all_consuming(many0(newline))(bytes)?;
    Ok((bytes, Circuit { operations }))
}

fn parse_comment(line: &[u8]) -> Res<&[u8], &str> {
    let (line, _) = delimited(space0, tag("#"), space0)(line)?;
    map_res(alphanumeric1, std::str::from_utf8)(line)
}

fn parse_operation(line: &[u8]) -> Res<&[u8], Operation> {
    let (line, operator) = delimited(space0, parse_operator, space0)(line)?;
    let (line, operands) = separated_list0(
        tag(","),
        delimited(space0, map_res(alphanumeric1, std::str::from_utf8), space0),
    )(line)?;

    let (line, comment) = parse_comment(line)?;
    Ok((line, Operation { operator, operands }))
}

fn parse_operator(line: &[u8]) -> Res<&[u8], Operator> {
    alt((
        value(Operator::AddS, tag("adds")),
        value(Operator::AddCI, tag("addci")),
        value(Operator::AddM, tag("addm")),
        value(Operator::BitDecInt, tag("bitdecint")),
        value(Operator::Bit, tag("bit")),
        value(Operator::ConvModp, tag("convmodp")),
        value(Operator::ConvInt, tag("convint")),
        value(Operator::LdSI, tag("ldsi")),
        value(Operator::LdI, tag("ldi")),
        value(Operator::MulSI, tag("mulsi")),
        value(Operator::MulS, tag("muls")),
        value(Operator::MulCI, tag("mulci")),
        value(Operator::MulM, tag("mulm")),
        value(Operator::Open, tag("asm_open")),
        value(Operator::PrintRegPlain, tag("print_reg_plain")),
        value(Operator::SubS, tag("subs")),
        value(Operator::ShrCI, tag("shrci")),
    ))(line)
}

fn parse_usize(line: &[u8]) -> Res<&[u8], usize> {
    let (line, res) = delimited(space0, u64, space0)(line)?;
    Ok((line, res as usize))
}

impl<'l> TryFrom<&'l [u8]> for Circuit<'l> {
    type Error = anyhow::Error;
    fn try_from(bytes: &'l [u8]) -> Result<Circuit<'l>, Self::Error> {
        parse_circuit(bytes)
            .map_err(|e| anyhow::anyhow!("Unexpected error during parsing {}", e))
            .map(|res| res.1)
    }
}

struct ShamirSharing {}

fn bit_generation() -> ShamirSharing {
    unimplemented!()
}

fn bitdec10() -> Result<(), anyhow::Error> {
    let circuit = Circuit::try_from(BIT_DEC_CIRCUIT)?;

    println!("LALAL");

    let mut secret_memory: HashMap<&str, ShamirSharing> = HashMap::new();

    for op in circuit.operations {
        use Operator::*;
        match op.operator {
            Bit => {
                let out_register = *op.operands.get(0).unwrap();
                let b = bit_generation();
                secret_memory.insert(out_register, b);
                println!("Out register: {:?}", out_register);
                // ok_or(Err(anyhow!("Wrong index buddy")))?;

                // let y_wire = *op.input_wires.get(1).unwrap();
                // let x = wires.get(x_wire).unwrap().clone().unwrap();
                // let y = wires.get(y_wire).unwrap().clone().unwrap();

                // let z = plc.xor(sess, &x, &y);
                // let z_wire = *op.output_wires.first().unwrap();
                // *wires.get_mut(z_wire).unwrap() = Some(z);
            }
            AddS => {
                unimplemented!()
            }
            LdSI => continue,
            _ => {
                unimplemented!()
            }
        }
    }
    Ok(())
}

fn main() {
    // println!("{:?}", circuit.unwrap().operations);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_mpspdz() {
        let circuit = Circuit::try_from(BIT_DEC_CIRCUIT).unwrap();
        assert_eq!(circuit.operations.len(), 1138);
    }

    #[test]
    fn test_execution() {
        bitdec10().unwrap()
    }
}
