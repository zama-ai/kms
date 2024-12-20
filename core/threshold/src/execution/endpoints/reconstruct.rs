use tfhe::{integer::block_decomposition::BlockRecomposer, shortint::ClassicPBSParameters};

use crate::{
    algebra::{base_ring::Z128, galois_rings::degree_8::ResiduePolyF8},
    error::error_handler::anyhow_error_and_log,
    execution::tfhe_internals::{
        parameters::AugmentedCiphertextParameters, switch_and_squash::from_expanded_msg,
    },
};

/// Reconstructs a vector of plaintexts from raw, opened ciphertexts,
/// by using the contant term of the `openeds` and mapping it down
/// to the message space of a ciphertext block.
pub fn reconstruct_message(
    openeds: Option<Vec<ResiduePolyF8<Z128>>>,
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

/// Reconstructs a vector of plaintexts from raw, opened ciphertexts
/// and mapping it down to the message space of a ciphertext block.
/// Unlike the function [reconstruct_message], every term in `openeds`
/// is used for the reconstruction and at most `num_blocks` terms will
/// be used.
pub fn reconstruct_packed_message(
    openeds: Option<Vec<ResiduePolyF8<Z128>>>,
    params: &ClassicPBSParameters,
    num_blocks: usize,
) -> anyhow::Result<Vec<Z128>> {
    let total_mod_bits = params.total_block_bits() as usize;
    let mut processed_blocks = 0;
    let mut out = Vec::new();
    match openeds {
        Some(openeds) => {
            for opened in openeds {
                for coef in opened.coefs {
                    out.push(from_expanded_msg(coef.0, total_mod_bits));
                    processed_blocks += 1;
                    if processed_blocks >= num_blocks {
                        break;
                    }
                }
            }
        }
        _ => return Err(anyhow_error_and_log("No opened value".to_string())),
    };

    if processed_blocks < num_blocks {
        return Err(anyhow_error_and_log(format!(
            "expected to process {num_blocks} but only processed {processed_blocks}"
        )));
    }
    Ok(out)
}

/// Helper function that takes a vector of decrypted plaintexts (each of [bits_in_block] plaintext bits)
/// and combine them into the integer message of many bits.
pub fn combine_decryptions<T>(bits_in_block: u32, decryptions: Vec<Z128>) -> anyhow::Result<T>
where
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
{
    let mut recomposer = BlockRecomposer::<T>::new(bits_in_block);

    for block in decryptions {
        if !recomposer.add_unmasked(block.0) {
            // End of T::BITS reached no need to try more
            // recomposition
            break;
        };
    }
    Ok(recomposer.value())
}

#[test]
fn test_recomposer() {
    use crate::algebra::structure_traits::FromU128;
    let out =
        combine_decryptions::<tfhe::integer::U256>(1, vec![Z128::from_u128(1), Z128::from_u128(3)])
            .unwrap();
    assert_eq!(out, tfhe::integer::U256::from((3, 0)));

    let out =
        combine_decryptions::<tfhe::integer::U256>(1, vec![Z128::from_u128(0), Z128::from_u128(7)])
            .unwrap();
    assert_eq!(out, tfhe::integer::U256::from((2, 0)));

    let out = combine_decryptions::<u64>(1, vec![Z128::from_u128(0), Z128::from_u128(0)]).unwrap();
    assert_eq!(out, 0_u64);

    let out = combine_decryptions::<u32>(2, vec![Z128::from_u128(3), Z128::from_u128(11)]).unwrap();
    assert_eq!(out, 15_u32);

    let out = combine_decryptions::<u16>(3, vec![Z128::from_u128(1), Z128::from_u128(1)]).unwrap();
    assert_eq!(out, 9_u16);
}
