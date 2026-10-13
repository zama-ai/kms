//! Public-decryption benchmark helpers.

use super::*;
use crate::cryptography::signing::test_support::seeded_identity;
use alloy_sol_types::SolStruct;
use rand::SeedableRng;
use tfhe::integer::U256 as TfheU256;

/// Input for one signing operation, with fixture setup outside the timed region.
#[derive(Clone)]
pub struct SignInput {
    identity: NodeSigningIdentity,
    schemes: Vec<SigningSchemeType>,
    payload: PublicDecryptionResponsePayload,
    handles: Vec<Vec<u8>>,
    extra_data: Vec<u8>,
    domain: Eip712Domain,
    response_bytes: Vec<u8>,
    sol_type: PublicDecryptVerification,
    eip712_hash: B256,
    signed_payload: PublicDecSignedPayload,
}

/// Selects the exact signing stage to measure.
#[derive(Clone, Copy)]
pub enum SignStage {
    Full,
    LegacySignature,
    Eip712Signature,
    SchemeEntries,
}

impl SignInput {
    /// Creates a deterministic signing request with a specified batch size and scheme set.
    pub fn new(batch_size: usize, wide: bool, schemes: &[SigningSchemeType]) -> Self {
        let mut rng = AesRng::seed_from_u64(0x0050_3dec);
        let identity = seeded_identity(&mut rng);
        let plaintexts = (0..batch_size)
            .map(|i| {
                if wide {
                    TypedPlaintext::from_u256(TfheU256::from(i as u64 + 42))
                } else {
                    TypedPlaintext::from_u64(i as u64 + 42)
                }
            })
            .collect();
        let payload = PublicDecryptionResponsePayload {
            plaintexts,
            verification_key: bc2wrap::serialize(&identity.verf_key()).unwrap(),
            request_id: Some(RequestId::new_random(&mut rng).into()),
        };
        let handles: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| {
                let mut handle = vec![0u8; 32];
                handle[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                handle
            })
            .collect();
        let extra_data = vec![0x45; 32];
        let domain = crate::dummy_domain();
        let response_bytes = bc2wrap::serialize(&payload).unwrap();
        let sol_type =
            compute_public_decryption_message(&handles, &payload.plaintexts, &extra_data).unwrap();
        let eip712_hash = sol_type.eip712_signing_hash(&domain);
        let signed_payload = public_dec_payload(&response_bytes, &extra_data);
        // Warm the derived-key cache before timing request signing.
        crate::cryptography::signing::composite::sign_result_entries(
            &identity,
            schemes,
            &DSEP_PUBLIC_DECRYPTION,
            &eip712_hash,
            &signed_payload,
        )
        .unwrap();
        Self {
            identity,
            schemes: schemes.to_vec(),
            payload,
            handles,
            extra_data,
            domain,
            response_bytes,
            sol_type,
            eip712_hash,
            signed_payload,
        }
    }

    /// Runs one production signing stage and consumes its output.
    pub fn run(self, stage: SignStage) -> anyhow::Result<()> {
        match stage {
            SignStage::Full => {
                std::hint::black_box(sign_public_decryption_result(
                    &self.identity,
                    &self.schemes,
                    self.payload,
                    &self.handles,
                    self.extra_data,
                    &self.domain,
                )?);
            }
            SignStage::LegacySignature => {
                std::hint::black_box(internal_sign(
                    &DSEP_PUBLIC_DECRYPTION,
                    &self.response_bytes,
                    self.identity.ecdsa(),
                )?);
            }
            SignStage::Eip712Signature => {
                let hash = self.sol_type.eip712_signing_hash(&self.domain);
                std::hint::black_box(crate::cryptography::signatures::eip712_sign_hash(
                    self.identity.ecdsa(),
                    &hash,
                )?);
            }
            SignStage::SchemeEntries => {
                std::hint::black_box(
                    crate::cryptography::signing::composite::sign_result_entries(
                        &self.identity,
                        &self.schemes,
                        &DSEP_PUBLIC_DECRYPTION,
                        &self.eip712_hash,
                        &self.signed_payload,
                    )?,
                );
            }
        }
        Ok(())
    }
}
