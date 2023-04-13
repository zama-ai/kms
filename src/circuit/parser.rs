use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::alphanumeric1;
use nom::character::complete::{newline, space0};
use nom::combinator::map_res;
use nom::combinator::{all_consuming, value};
use nom::multi::{many0, separated_list0};
use nom::sequence::delimited;
use nom::sequence::pair;

use super::{Circuit, Operation, Operator};

type Res<T, U> = nom::IResult<T, U, nom::error::Error<T>>;

fn parse_circuit(bytes: &[u8]) -> Res<&[u8], Circuit> {
    let (bytes, _) = many0(pair(parse_comment, newline))(bytes)?;
    let (bytes, operations) = separated_list0(newline, parse_operation)(bytes)?;
    let (bytes, _) = all_consuming(many0(newline))(bytes)?;
    Ok((
        bytes,
        Circuit {
            input_wires: vec!["s6".into()],
            operations,
        },
    ))
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

    let (line, _comment) = parse_comment(line)?;
    // TODO(Dragos) see how we can get rid of this map
    Ok((
        line,
        Operation {
            operator,
            operands: operands.iter().map(|x| x.to_string()).collect(),
        },
    ))
}

// these must be ordered such that no previous operator is a prefix of a later operator, e.g., bit must be after bitdecint in the list!
fn parse_operator(line: &[u8]) -> Res<&[u8], Operator> {
    alt((
        value(Operator::AddS, tag("adds")),
        value(Operator::AddCI, tag("addci")),
        value(Operator::AddM, tag("addm")),
        value(Operator::BitDecInt, tag("bitdecint")),
        value(Operator::Bit, tag("bit")),
        value(Operator::ConvModp, tag("convmodp")),
        value(Operator::ConvInt, tag("convint")),
        value(Operator::DistPrep, tag("dist_prep")),
        value(Operator::LdSI, tag("ldsi")),
        value(Operator::LdI, tag("ldi")),
        value(Operator::LdCI, tag("ldci")),
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

impl TryFrom<&[u8]> for Circuit {
    type Error = anyhow::Error;
    fn try_from(bytes: &[u8]) -> Result<Circuit, Self::Error> {
        parse_circuit(bytes)
            .map_err(|e| anyhow::anyhow!("Unexpected error during parsing {}", e))
            .map(|res| res.1)
    }
}
