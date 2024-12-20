use crate::{
    algebra::{structure_traits::Field, syndrome::decode_syndrome},
    execution::sharing::shamir::ShamirFieldPoly,
};

pub fn syndrome_decoding_z2<F: Field + From<u8>>(
    parties: &[usize],
    syndrome: &ShamirFieldPoly<F>,
    threshold: usize,
) -> Vec<F> {
    let xs: Vec<F> = parties.iter().map(|s| F::from(*s as u8)).collect();
    let r = parties.len() - (threshold + 1);
    decode_syndrome(syndrome, &xs, r)
}
