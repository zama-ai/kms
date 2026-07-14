use super::{SOLANA_CHAIN_TYPE_BIT, handle_chain_id};

/// A host chain ID that is valid for the Solana request path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SolanaHostChainId(u64);

impl SolanaHostChainId {
    fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SolanaHostChainId {
    type Error = SolanaUserDecryptBindingError;

    fn try_from(chain_id: u64) -> Result<Self, Self::Error> {
        if chain_id & SOLANA_CHAIN_TYPE_BIT == 0 {
            return Err(SolanaUserDecryptBindingError::InvalidDeclaredChainId { chain_id });
        }
        Ok(Self(chain_id))
    }
}

/// Canonical Solana ciphertext handles and the common chain ID embedded in them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolanaUserDecryptBinding {
    handles: Vec<[u8; 32]>,
    chain_id: SolanaHostChainId,
}

impl SolanaUserDecryptBinding {
    pub fn try_from_handle_bytes<'a>(
        handles: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, SolanaUserDecryptBindingError> {
        let mut canonical_handles = Vec::new();
        let mut common_chain_id = None;

        for (index, handle) in handles.into_iter().enumerate() {
            let handle: [u8; 32] = handle.try_into().map_err(|_| {
                SolanaUserDecryptBindingError::InvalidHandleLength {
                    index,
                    actual: handle.len(),
                }
            })?;
            let chain_id = handle_chain_id(&handle);
            if chain_id & SOLANA_CHAIN_TYPE_BIT == 0 {
                return Err(SolanaUserDecryptBindingError::InvalidHandleChainId {
                    index,
                    chain_id,
                });
            }
            if let Some(expected) = common_chain_id {
                if chain_id != expected {
                    return Err(SolanaUserDecryptBindingError::MixedChainIds {
                        index,
                        expected,
                        actual: chain_id,
                    });
                }
            } else {
                common_chain_id = Some(chain_id);
            }
            canonical_handles.push(handle);
        }

        let chain_id = common_chain_id
            .map(SolanaHostChainId)
            .ok_or(SolanaUserDecryptBindingError::EmptyHandles)?;
        Ok(Self {
            handles: canonical_handles,
            chain_id,
        })
    }

    fn handles(&self) -> &[[u8; 32]] {
        &self.handles
    }

    fn chain_id(&self) -> SolanaHostChainId {
        self.chain_id
    }

    pub fn validate_declared_chain_id(
        &self,
        declared: u64,
    ) -> Result<(), SolanaUserDecryptBindingError> {
        let declared = SolanaHostChainId::try_from(declared)?;
        if declared != self.chain_id {
            return Err(SolanaUserDecryptBindingError::DeclaredChainIdMismatch {
                declared: declared.get(),
                embedded: self.chain_id.get(),
            });
        }
        Ok(())
    }

    pub fn compute_link(&self, enc_key: &[u8], solana_user_pubkey: &[u8; 32]) -> Vec<u8> {
        compute_link_solana(
            enc_key,
            self.handles(),
            solana_user_pubkey,
            self.chain_id().get(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SolanaUserDecryptBindingError {
    #[error("Solana user-decrypt request contains no ciphertext handles")]
    EmptyHandles,
    #[error("Solana ciphertext handle at index {index} must be 32 bytes, got {actual}")]
    InvalidHandleLength { index: usize, actual: usize },
    #[error(
        "Solana ciphertext handle at index {index} embeds chain ID {chain_id}, which does not set bit 63"
    )]
    InvalidHandleChainId { index: usize, chain_id: u64 },
    #[error(
        "Solana ciphertext handle at index {index} embeds chain ID {actual}, expected {expected}"
    )]
    MixedChainIds {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("declared Solana host chain ID {chain_id} does not set bit 63")]
    InvalidDeclaredChainId { chain_id: u64 },
    #[error("declared Solana host chain ID {declared} does not match handle chain ID {embedded}")]
    DeclaredChainIdMismatch { declared: u64, embedded: u64 },
}

/// Computes the Solana-native user-decryption request↔response link.
///
/// On EVM, [`crate::kms::v1::UserDecryptionRequest::compute_link_checked`] binds the
/// triple `(publicKey, handles, userAddress)` via an EIP-712 hash over the gateway domain
/// (an EVM `verifying_contract` + `chainId`). A Solana host has no EVM verifying contract
/// and the user identity is a 32-byte ed25519 pubkey rather than a 20-byte `address`, so
/// the EIP-712 linker cannot represent it.
///
/// This binds the same logical triple — the user's ML-KEM `enc_key`, the ciphertext
/// `handles`, and the 32-byte Solana user pubkey — under the Solana host chain id, with
/// keccak256 (matching the keccak domain used across the Solana on-chain surface). It is
/// purely the request↔response binding, so a relayed response cannot be swapped onto a
/// different request; it is NOT the authorization. Authorization for a Solana user
/// decryption is enforced by the kms-connector before the core call: the RPC-verified
/// on-chain ACL (the user holds the use/decrypt role on the handle's `zama-host` ACL
/// record) plus the user's ed25519 `signMessage` over the canonical native request.
///
/// Length-prefixed fields keep the preimage unambiguous; a version tag domain-separates
/// it from every other keccak preimage on the Solana surface.
///
/// # Validation
///
/// This private helper only computes the preimage hash; validation is performed when constructing
/// [`SolanaUserDecryptBinding`]. Request boundaries must use the binding's checked `compute_link`
/// method rather than hashing unvalidated handles directly.
fn compute_link_solana(
    enc_key: &[u8],
    handles: &[[u8; 32]],
    solana_user_pubkey: &[u8; 32],
    host_chain_id: u64,
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(64 + handles.len() * 32 + enc_key.len());
    preimage.extend_from_slice(b"SolanaUserDecryptionLinker:v0");
    preimage.extend_from_slice(&host_chain_id.to_be_bytes());
    preimage.extend_from_slice(solana_user_pubkey);
    preimage.extend_from_slice(&(handles.len() as u32).to_be_bytes());
    for handle in handles {
        preimage.extend_from_slice(handle);
    }
    preimage.extend_from_slice(&(enc_key.len() as u32).to_be_bytes());
    preimage.extend_from_slice(enc_key);
    alloy_primitives::keccak256(&preimage).to_vec()
}

#[cfg(test)]
mod solana_link_tests {
    use super::{
        SOLANA_CHAIN_TYPE_BIT, SolanaHostChainId, SolanaUserDecryptBinding,
        SolanaUserDecryptBindingError, compute_link_solana,
    };

    const SOLANA_POC_CHAIN_ID: u64 = SOLANA_CHAIN_TYPE_BIT | 12_345;

    fn handle(chain_id: u64, discriminator: u8) -> [u8; 32] {
        let mut handle = [discriminator; 32];
        handle[22..30].copy_from_slice(&chain_id.to_be_bytes());
        handle
    }

    fn binding(handles: &[[u8; 32]]) -> SolanaUserDecryptBinding {
        SolanaUserDecryptBinding::try_from_handle_bytes(
            handles.iter().map(|handle| handle.as_slice()),
        )
        .unwrap()
    }

    #[test]
    fn solana_link_is_deterministic_and_field_sensitive() {
        let enc_key = vec![7u8; 800];
        let handles = vec![
            handle(SOLANA_POC_CHAIN_ID, 1),
            handle(SOLANA_POC_CHAIN_ID, 2),
        ];
        let base_binding = binding(&handles);
        let pubkey = [9u8; 32];

        let base = base_binding.compute_link(&enc_key, &pubkey);
        assert_eq!(base.len(), 32, "keccak256 output is 32 bytes");
        // KMS wire-format regression vector for the exact fixture above. This must be promoted to
        // a cross-repository specification vector before the Solana branch is upstreamed.
        assert_eq!(
            hex::encode(&base),
            "ed19cee8b6b8e8da67f754547551297060ebfb057f93a423909791a7a0c34385"
        );
        assert_eq!(
            base,
            compute_link_solana(&enc_key, &handles, &pubkey, SOLANA_POC_CHAIN_ID,)
        );
        // Deterministic.
        assert_eq!(base, base_binding.compute_link(&enc_key, &pubkey));

        // Sensitive to every bound field.
        let mut other_pubkey = pubkey;
        other_pubkey[0] ^= 0xff;
        assert_ne!(base, base_binding.compute_link(&enc_key, &other_pubkey));
        let one_handle = binding(&handles[..1]);
        assert_ne!(
            base,
            one_handle.compute_link(&enc_key, &pubkey),
            "dropping a handle must change the link"
        );
        assert_ne!(
            base,
            base_binding.compute_link(&[7u8; 799], &pubkey),
            "a different enc_key must change the link"
        );
        let other_chain_handles = vec![
            handle(SOLANA_POC_CHAIN_ID + 1, 1),
            handle(SOLANA_POC_CHAIN_ID + 1, 2),
        ];
        let other_chain = binding(&other_chain_handles);
        assert_ne!(base, other_chain.compute_link(&enc_key, &pubkey));
    }

    #[test]
    fn solana_link_length_prefixing_prevents_field_boundary_collision() {
        // Two handles [a,b] vs one handle that is the concatenation a‖b would collide
        // without length-prefixing; the count prefix must keep them distinct.
        let enc_key = vec![0u8; 4];
        let pubkey = [3u8; 32];
        let two_handles = vec![
            handle(SOLANA_POC_CHAIN_ID, 0xaa),
            handle(SOLANA_POC_CHAIN_ID, 0xbb),
        ];
        let two = binding(&two_handles).compute_link(&enc_key, &pubkey);
        // One 32-byte handle plus enc_key shifted can't reproduce the two-handle preimage
        // because the handle count (2 vs 1) is hashed in.
        let one = binding(&two_handles[..1]).compute_link(&enc_key, &pubkey);
        assert_ne!(two, one);
    }

    #[test]
    fn validates_the_solana_chain_kind_and_exact_handle_width() {
        let valid = handle(SOLANA_POC_CHAIN_ID, 1);
        let parsed = binding(&[valid]);
        assert_eq!(parsed.chain_id().get(), 9_223_372_036_854_788_153);

        assert_eq!(
            SolanaHostChainId::try_from(12_345),
            Err(SolanaUserDecryptBindingError::InvalidDeclaredChainId { chain_id: 12_345 })
        );
        assert_eq!(
            SolanaUserDecryptBinding::try_from_handle_bytes(std::iter::once(&valid[..31])),
            Err(SolanaUserDecryptBindingError::InvalidHandleLength {
                index: 0,
                actual: 31,
            })
        );
        assert_eq!(
            SolanaUserDecryptBinding::try_from_handle_bytes(std::iter::once(&[0u8; 33][..])),
            Err(SolanaUserDecryptBindingError::InvalidHandleLength {
                index: 0,
                actual: 33,
            })
        );
    }

    #[test]
    fn rejects_low_bit_and_mixed_chain_batches() {
        let low_bit = handle(12_345, 2);
        assert_eq!(
            SolanaUserDecryptBinding::try_from_handle_bytes(std::iter::once(low_bit.as_slice())),
            Err(SolanaUserDecryptBindingError::InvalidHandleChainId {
                index: 0,
                chain_id: 12_345,
            })
        );

        let valid = handle(SOLANA_POC_CHAIN_ID, 1);
        let later_low_bit = handle(12_345, 2);
        assert_eq!(
            SolanaUserDecryptBinding::try_from_handle_bytes([
                valid.as_slice(),
                later_low_bit.as_slice()
            ]),
            Err(SolanaUserDecryptBindingError::InvalidHandleChainId {
                index: 1,
                chain_id: 12_345,
            })
        );

        let other = handle(SOLANA_POC_CHAIN_ID + 1, 2);
        assert_eq!(
            SolanaUserDecryptBinding::try_from_handle_bytes([valid.as_slice(), other.as_slice()]),
            Err(SolanaUserDecryptBindingError::MixedChainIds {
                index: 1,
                expected: SOLANA_POC_CHAIN_ID,
                actual: SOLANA_POC_CHAIN_ID + 1,
            })
        );
    }

    #[test]
    fn rejects_empty_handles_and_declared_chain_id_mismatches() {
        assert_eq!(
            SolanaUserDecryptBinding::try_from_handle_bytes(std::iter::empty()),
            Err(SolanaUserDecryptBindingError::EmptyHandles)
        );

        let valid = handle(SOLANA_POC_CHAIN_ID, 1);
        let binding = binding(&[valid]);
        assert_eq!(
            binding.validate_declared_chain_id(SOLANA_POC_CHAIN_ID),
            Ok(())
        );
        assert_eq!(
            binding.validate_declared_chain_id(12_345),
            Err(SolanaUserDecryptBindingError::InvalidDeclaredChainId { chain_id: 12_345 })
        );
        assert_eq!(
            binding.validate_declared_chain_id(SOLANA_POC_CHAIN_ID + 1),
            Err(SolanaUserDecryptBindingError::DeclaredChainIdMismatch {
                declared: SOLANA_POC_CHAIN_ID + 1,
                embedded: SOLANA_POC_CHAIN_ID,
            })
        );
    }
}
