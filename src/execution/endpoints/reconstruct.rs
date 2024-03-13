use tfhe::shortint::ClassicPBSParameters;

use crate::{
    algebra::{base_ring::Z128, residue_poly::ResiduePoly},
    error::error_handler::anyhow_error_and_log,
    execution::tfhe_internals::{
        parameters::AugmentedCiphertextParameters, switch_and_squash::from_expanded_msg,
    },
};

/// Reconstructs a vector of plaintexts from raw, opened ciphertexts, by using the contant term of the `openeds`
/// and mapping it down to the message space of a ciphertext block.
pub fn reconstruct_message(
    openeds: Option<Vec<ResiduePoly<Z128>>>,
    params: &ClassicPBSParameters,
) -> anyhow::Result<Vec<Z128>> {
    let total_mod_bits = params.total_block_bits() as usize;
    // shift
    let mut out = Vec::new();
    match openeds {
        Some(openeds) => {
            for opened in openeds {
                let v_scalar = opened.to_scalar()?;
                out.push(from_expanded_msg(v_scalar.0, total_mod_bits));
            }
        }
        _ => {
            return Err(anyhow_error_and_log(
                "Right shift not possible - no opened value".to_string(),
            ))
        }
    };
    Ok(out)
}
