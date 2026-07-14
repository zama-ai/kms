use crate::cryptography::encryption::UnifiedPublicEncKey;
use kms_grpc::kms::v1::{UserDecryptionRequest, user_decryption_request::ClientIdentity};
use kms_grpc::rpc_types::{SolanaUserDecryptBinding, optional_protobuf_to_alloy_domain};

/// Solana-derived fields needed by the route-neutral validated request.
pub(super) struct ValidatedSolanaUserDecrypt {
    /// Request-response binding computed from canonical Solana handles and identity.
    pub(super) link: Vec<u8>,
    /// Stable 20-byte signcryption label derived from the Solana pubkey.
    pub(super) client_id: alloy_primitives::Address,
    /// Gateway domain used to verify the standard KMS response certificate.
    pub(super) domain: alloy_sol_types::Eip712Domain,
}

/// Derives the stable 20-byte signcryption `client_id` from a 32-byte Solana pubkey as
/// `keccak256(pubkey)[12..]`, mirroring EVM address derivation. The client reproduces this
/// to de-signcrypt the response; it is a deterministic label, not an authorization input
/// (Solana user-decrypt authorization is enforced by the kms-connector before this call).
fn client_id(solana_pubkey: &[u8; 32]) -> alloy_primitives::Address {
    alloy_primitives::Address::from_slice(&alloy_primitives::keccak256(solana_pubkey)[12..])
}

/// Validates Solana-specific user-decryption fields, or returns `None` for the EVM route.
pub(super) fn validate_if_solana(
    req: &UserDecryptionRequest,
) -> Result<Option<ValidatedSolanaUserDecrypt>, Box<dyn std::error::Error + Send + Sync>> {
    // Solana-native user decryption: the client identity is a typed 32-byte ed25519 pubkey and
    // there is no EVM verifying contract. Authorization (RPC-verified on-chain ACL + ed25519 signMessage) is
    // enforced by the kms-connector before this call — exactly as the gateway enforces the EVM
    // ACL before the EVM path — so here we only bind the response to the request via the Solana
    // link (`compute_link_solana`). The link is passed opaquely into signcryption, so the
    // binding is sound as long as the client recomputes the same link. The response cert is the
    // standard secp256k1 EIP-712 the gateway verifies, signed under the gateway's `Decryption`
    // domain (`req.domain`) — see the domain note below.
    // Typed-identity routing fails closed: only `solana_pubkey` selects this path. An EVM identity
    // or an unset identity follows the unchanged EVM route.
    let solana_pubkey = match &req.client_identity {
        Some(ClientIdentity::SolanaPubkey(pubkey)) => <[u8; 32]>::try_from(pubkey.as_slice())
            .map_err(|_| {
                anyhow::anyhow!(
                    "Solana client identity must be a 32-byte pubkey, got {} bytes",
                    pubkey.len()
                )
            })?,
        Some(ClientIdentity::EvmAddress(_)) | None => return Ok(None),
    };

    let binding = SolanaUserDecryptBinding::try_from_handle_bytes(
        req.typed_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.external_handle.as_slice()),
    )?;
    let link = binding.compute_link(&req.enc_key, &solana_pubkey);
    let client_id = client_id(&solana_pubkey);
    let _client_enc_key =
        UnifiedPublicEncKey::deserialize_and_validate(&req.enc_key).map_err(|e| {
            anyhow::anyhow!(
                "Error deserializing UnifiedPublicEncKey from Solana UserDecryptionRequest: {e}"
            )
        })?;
    // The KMS signs `UserDecryptResponseVerification` under the gateway's `Decryption`
    // EIP-712 domain (name/version/chainId/verifyingContract, carried in `req.domain`) so the
    // gateway's `userDecryptionResponse` recovers the registered KMS signer on-chain. The
    // response cert is the standard secp256k1 EIP-712 — identical to EVM; only the user
    // *authorization* seam differs (ed25519, already enforced by the connector), so there is
    // no user EIP-712 to verify here.
    let response_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    Ok(Some(ValidatedSolanaUserDecrypt {
        link,
        client_id,
        domain: response_domain,
    }))
}

#[cfg(test)]
mod tests {
    use super::{client_id, validate_if_solana};
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{
        TypedCiphertext, UserDecryptionRequest, user_decryption_request::ClientIdentity,
    };
    use kms_grpc::rpc_types::{
        SolanaUserDecryptBinding, SolanaUserDecryptBindingError, alloy_to_protobuf_domain,
    };
    use rand::SeedableRng;

    use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
    use crate::dummy_domain;
    use crate::engine::base::derive_request_id;

    const SOLANA_CHAIN_ID: u64 = (1 << 63) | 12_345;

    fn handle(chain_id: u64) -> Vec<u8> {
        let mut handle = [0xabu8; 32];
        handle[22..30].copy_from_slice(&chain_id.to_be_bytes());
        handle.to_vec()
    }

    fn request(client_identity: Option<ClientIdentity>) -> UserDecryptionRequest {
        let mut rng = AesRng::seed_from_u64(0);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_, enc_key) = encryption.keygen().unwrap();
        let mut enc_key_bytes = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &enc_key,
            &mut enc_key_bytes,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        UserDecryptionRequest {
            request_id: Some(derive_request_id("request_id").unwrap().into()),
            typed_ciphertexts: vec![TypedCiphertext {
                ciphertext: vec![],
                fhe_type: 0,
                external_handle: handle(SOLANA_CHAIN_ID),
                ciphertext_format: 0,
            }],
            key_id: Some(derive_request_id("key_id").unwrap().into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            client_address: String::new(),
            enc_key: enc_key_bytes,
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
            client_identity,
        }
    }

    fn validate(
        req: &UserDecryptionRequest,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(validate_if_solana(req)?.is_some())
    }

    #[test]
    fn client_id_is_keccak_derived_and_deterministic() {
        let pubkey = [0x22u8; 32];
        let id = client_id(&pubkey);
        assert_eq!(id, client_id(&pubkey));
        assert_eq!(id.as_slice(), &alloy_primitives::keccak256(pubkey)[12..]);
        let mut other = pubkey;
        other[0] ^= 0xff;
        assert_ne!(id, client_id(&other));
    }

    #[test]
    fn typed_solana_identity_requires_exactly_32_bytes() {
        for actual in [31, 33] {
            let req = request(Some(ClientIdentity::SolanaPubkey(vec![0x11; actual])));
            assert_eq!(
                validate(&req).unwrap_err().to_string(),
                format!("Solana client identity must be a 32-byte pubkey, got {actual} bytes")
            );
        }
    }

    #[test]
    fn typed_evm_identity_takes_precedence_over_legacy_solana_string() {
        let mut req = request(Some(ClientIdentity::EvmAddress(vec![0x22; 20])));
        req.client_address = format!("solana:{}", alloy_primitives::hex::encode([0x11; 32]));
        assert!(!validate(&req).unwrap());
    }

    #[test]
    fn unset_identity_does_not_route_a_legacy_solana_string_to_solana() {
        let mut req = request(None);
        req.client_address = format!("solana:{}", alloy_primitives::hex::encode([0x11; 32]));
        assert!(!validate(&req).unwrap());
    }

    #[test]
    fn returns_the_solana_derived_validation_fields() {
        let pubkey = [0x11; 32];
        let req = request(Some(ClientIdentity::SolanaPubkey(pubkey.to_vec())));
        let validated = validate_if_solana(&req).unwrap().unwrap();
        let binding = SolanaUserDecryptBinding::try_from_handle_bytes(
            req.typed_ciphertexts
                .iter()
                .map(|ciphertext| ciphertext.external_handle.as_slice()),
        )
        .unwrap();

        assert_eq!(validated.link, binding.compute_link(&req.enc_key, &pubkey));
        assert_eq!(
            validated.client_id.as_slice(),
            &alloy_primitives::keccak256(pubkey)[12..]
        );
        assert_eq!(validated.domain, dummy_domain());
    }

    #[test]
    fn solana_encryption_key_error_keeps_its_prefix() {
        let mut req = request(Some(ClientIdentity::SolanaPubkey(vec![0x11; 32])));
        req.enc_key.clear();
        assert!(validate(&req).unwrap_err().to_string().starts_with(
            "Error deserializing UnifiedPublicEncKey from Solana UserDecryptionRequest:"
        ));
    }

    #[test]
    fn missing_response_domain_keeps_its_error() {
        let mut req = request(Some(ClientIdentity::SolanaPubkey(vec![0x11; 32])));
        req.domain = None;
        assert_eq!(validate(&req).unwrap_err().to_string(), "missing domain");
    }

    #[test]
    fn validates_chain_kind_width_and_batch_consistency() {
        let req = request(Some(ClientIdentity::SolanaPubkey(vec![0x11; 32])));
        assert!(validate(&req).unwrap());

        let mut low_bit = req.clone();
        low_bit.typed_ciphertexts[0].external_handle = handle(12_345);
        assert_eq!(
            validate(&low_bit)
                .unwrap_err()
                .downcast_ref::<SolanaUserDecryptBindingError>(),
            Some(&SolanaUserDecryptBindingError::InvalidHandleChainId {
                index: 0,
                chain_id: 12_345,
            })
        );

        let mut mixed = req.clone();
        mixed.typed_ciphertexts.push(TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: handle(SOLANA_CHAIN_ID + 1),
            ciphertext_format: 0,
        });
        assert_eq!(
            validate(&mixed)
                .unwrap_err()
                .downcast_ref::<SolanaUserDecryptBindingError>(),
            Some(&SolanaUserDecryptBindingError::MixedChainIds {
                index: 1,
                expected: SOLANA_CHAIN_ID,
                actual: SOLANA_CHAIN_ID + 1,
            })
        );

        let mut short = req;
        short.typed_ciphertexts[0].external_handle.pop();
        assert_eq!(
            validate(&short)
                .unwrap_err()
                .downcast_ref::<SolanaUserDecryptBindingError>(),
            Some(&SolanaUserDecryptBindingError::InvalidHandleLength {
                index: 0,
                actual: 31,
            })
        );
    }
}
