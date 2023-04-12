use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

mod parser;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Circuit {
    pub operations: Vec<Operation>,
    pub input_wires: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Operation {
    pub operator: Operator,
    pub operands: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Operator {
    AddCI,
    AddM,
    AddS,
    Bit,
    BitDecInt,
    ConvInt,
    ConvModp,
    LdI,
    LdCI,
    LdSI,
    MulCI,
    MulM,
    MulS,
    MulSI,
    Open,
    PrintRegPlain,
    ShrCI,
    SubS,
}

const BIT_DEC_CIRCUIT_BYTES: &[u8] = include_bytes!("./bitdec.txt");

lazy_static! {
    pub(crate) static ref BIT_DEC_CIRCUIT: Circuit =
        Circuit::try_from(BIT_DEC_CIRCUIT_BYTES).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bit_dec() {
        let circuit = Circuit::try_from(BIT_DEC_CIRCUIT_BYTES).unwrap();
        assert_eq!(circuit.operations.len(), 1137);
    }
}
