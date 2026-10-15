//! Protocol rules of pad decryption (tech-spec RFC-030) that the server and the client share.

use alloy_primitives::B256;
use alloy_sol_types::{Eip712Domain, SolStruct};
use kms_grpc::{
    RequestId, kms::v1::PadDecryptionResponsePayload, rpc_types::fhe_type_to_num_bits,
    solidity_types,
};
use tfhe::FheTypes;

/// The maximum sum of `pad_length` over all pads of one request, in bits.
pub const MAX_PAD_REQUEST_BITS: u64 = 2048;

/// The length of a label, in bytes.
pub const LABEL_BYTES: usize = 32;

/// Returns the FHE type of each pad block of the PRF instance `prf`.
///
/// # Errors
///
/// Errors when the KMS does not support `prf`.
pub fn pad_block_fhe_type(prf: u32) -> anyhow::Result<FheTypes> {
    match prf {
        0 => Ok(FheTypes::Uint64),
        _ => anyhow::bail!("Unsupported PRF instance identifier {prf}"),
    }
}

/// Returns the number of pad blocks of the PRF instance `prf` that cover `pad_length` bits.
///
/// # Errors
///
/// Errors when the KMS does not support `prf`.
pub fn num_pad_blocks(prf: u32, pad_length: u32) -> anyhow::Result<usize> {
    let block_bits = fhe_type_to_num_bits(pad_block_fhe_type(prf)?)?;
    Ok((pad_length as usize).div_ceil(block_bits))
}

/// Returns the EIP-712 signing hash of `payload` under `domain`, over the
/// [`solidity_types::PadDecryptResponsePayload`] struct.
///
/// # Errors
///
/// Errors when `payload` has no valid request ID, or when a label is not [`LABEL_BYTES`] long.
pub fn pad_payload_signing_hash(
    payload: &PadDecryptionResponsePayload,
    domain: &Eip712Domain,
) -> anyhow::Result<B256> {
    Ok(to_sol_payload(payload)?.eip712_signing_hash(domain))
}

fn to_sol_payload(
    payload: &PadDecryptionResponsePayload,
) -> anyhow::Result<solidity_types::PadDecryptResponsePayload> {
    let request_id: RequestId = payload
        .request_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing request ID in pad decryption payload"))?
        .try_into()?;
    let pad_shares = payload
        .pad_shares
        .iter()
        .map(|share| {
            Ok(solidity_types::PadShare {
                label: B256::try_from(share.label.as_slice()).map_err(|_| {
                    anyhow::anyhow!(
                        "Label has {} bytes, expected {LABEL_BYTES}",
                        share.label.len()
                    )
                })?,
                blockShares: share
                    .block_shares
                    .iter()
                    .map(|block| block.clone().into())
                    .collect(),
                packingFactor: share.packing_factor,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(solidity_types::PadDecryptResponsePayload {
        extraData: payload.extra_data.clone().into(),
        requestId: B256::from(*request_id.as_bytes()),
        degree: payload.degree,
        partyId: payload.party_id,
        padShares: pad_shares,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dummy_domain;
    use kms_grpc::kms::v1::PadShare;

    fn test_payload() -> PadDecryptionResponsePayload {
        PadDecryptionResponsePayload {
            extra_data: vec![2; 65],
            request_id: Some(RequestId::from_bytes([7; 32]).into()),
            degree: 1,
            party_id: 3,
            pad_shares: vec![PadShare {
                label: vec![9; LABEL_BYTES],
                block_shares: vec![vec![1, 2, 3], vec![4, 5]],
                packing_factor: 1,
            }],
        }
    }

    #[test]
    fn pad_block_fhe_type_supported() {
        assert_eq!(pad_block_fhe_type(0).unwrap(), FheTypes::Uint64);
    }

    #[test]
    fn pad_block_fhe_type_unsupported() {
        assert!(pad_block_fhe_type(1).is_err());
        assert!(pad_block_fhe_type(u32::MAX).is_err());
    }

    #[test]
    fn num_pad_blocks_rounds_up() {
        assert_eq!(num_pad_blocks(0, 1).unwrap(), 1);
        assert_eq!(num_pad_blocks(0, 64).unwrap(), 1);
        assert_eq!(num_pad_blocks(0, 65).unwrap(), 2);
        assert_eq!(num_pad_blocks(0, MAX_PAD_REQUEST_BITS as u32).unwrap(), 32);
        assert!(num_pad_blocks(1, 64).is_err());
    }

    #[test]
    fn signing_hash_binds_every_field() {
        let domain = dummy_domain();
        let base = pad_payload_signing_hash(&test_payload(), &domain).unwrap();
        assert_eq!(
            base,
            pad_payload_signing_hash(&test_payload(), &domain).unwrap()
        );

        let changes: Vec<fn(&mut PadDecryptionResponsePayload)> = vec![
            |p| p.extra_data.push(0),
            |p| p.request_id = Some(RequestId::from_bytes([8; 32]).into()),
            |p| p.degree += 1,
            |p| p.party_id += 1,
            |p| p.pad_shares[0].label[0] ^= 1,
            |p| p.pad_shares[0].block_shares[1].push(6),
            |p| p.pad_shares[0].block_shares.swap(0, 1),
            |p| p.pad_shares[0].packing_factor += 1,
            |p| p.pad_shares.clear(),
        ];
        for change in changes {
            let mut payload = test_payload();
            change(&mut payload);
            assert_ne!(base, pad_payload_signing_hash(&payload, &domain).unwrap());
        }
    }

    #[test]
    fn signing_hash_rejects_malformed_payload() {
        let domain = dummy_domain();

        let mut payload = test_payload();
        payload.request_id = None;
        assert!(pad_payload_signing_hash(&payload, &domain).is_err());

        let mut payload = test_payload();
        payload.pad_shares[0].label.pop();
        assert!(pad_payload_signing_hash(&payload, &domain).is_err());
    }
}
