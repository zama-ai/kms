use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
use crate::cryptography::encryption::UnifiedPublicEncKey;
use kms_grpc::identifiers::{ContextId, EpochId};
use kms_grpc::{
    kms::v1::UserDecryptionRequest,
    rpc_types::{SigncryptionReceiver, optional_protobuf_to_alloy_domain},
    solana_binding::{SOLANA_IDENTITY_LEN, SolanaUserDecryptBinding},
};

/// What the adapter hands to the shared engine: the request's link, the recipient the result is
/// sealed to, and the domain the response signature is produced under.
type SolanaValidation = (Vec<u8>, SigncryptionReceiver, alloy_sol_types::Eip712Domain);

/// Builds the canonical binding for a Solana user-decryption request.
///
/// Returns `Ok(None)` for a request that carries no Solana identity: that request belongs to the
/// EVM path, which this function must leave exactly as it found it.
///
/// The adapter is where host knowledge ends. It reads the typed Solana fields, hands them to the
/// checked binding, and returns bytes — it does not parse relayer payloads, wallet signatures,
/// PDAs, ACL or MMR evidence, or delegation policy, all of which are settled before a request
/// reaches any KMS party. It also does not parse `extra_data`: the KMS is agnostic to its content
/// by design, and the values the linker commits to arrive as typed fields, parsed by the connector
/// that verified the signature over them.
pub(super) fn validate_solana_request(
    req: &UserDecryptionRequest,
) -> Result<Option<SolanaValidation>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pubkey) = req.solana_pubkey.as_deref() else {
        // A request that carries the other Solana field without the identity is contradictory, not
        // EVM: reinterpreting it silently would surface a connector bug as a client-side link
        // mismatch instead of an error that names the field.
        if req.solana_verifying_program_id.is_some() {
            return Err(anyhow::anyhow!(
                "user decryption request sets solana_verifying_program_id without solana_pubkey"
            )
            .into());
        }
        return Ok(None);
    };
    let pubkey = <[u8; SOLANA_IDENTITY_LEN]>::try_from(pubkey).map_err(|_| {
        anyhow::anyhow!(
            "Solana client identity must be a 32-byte pubkey, got {} bytes",
            pubkey.len()
        )
    })?;
    if !req.client_address.is_empty() {
        return Err(
            anyhow::anyhow!("Solana user decryption request must not set client_address").into(),
        );
    }

    let verifying_program_id = req.solana_verifying_program_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "Solana user decryption request must set solana_verifying_program_id, half of the \
             deployment domain the response is bound to"
        )
    })?;

    // The KMS binds the same context and epoch it selects keys by, taken from the typed fields the
    // connector parsed out of the signed request. The defaults mirror the shared request path, so a
    // request that omits them is bound to the values the KMS actually used.
    let context_id: ContextId = match &req.context_id {
        Some(context_id) => context_id.try_into()?,
        None => *DEFAULT_MPC_CONTEXT,
    };
    let epoch_id: EpochId = match &req.epoch_id {
        Some(epoch_id) => epoch_id.try_into()?,
        None => *DEFAULT_EPOCH_ID,
    };

    let transport_key =
        UnifiedPublicEncKey::deserialize_and_validate(&req.enc_key).map_err(|error| {
            anyhow::anyhow!(
                "Error deserializing UnifiedPublicEncKey from Solana UserDecryptionRequest: {error}"
            )
        })?;
    require_mlkem512_transport_key(&transport_key)?;

    // The one construction, given the request's own bytes: the transport key exactly as the request
    // carries it, and the handles in request order with duplicates preserved.
    let binding = SolanaUserDecryptBinding::new(
        verifying_program_id,
        &pubkey,
        context_id.as_bytes(),
        epoch_id.as_bytes(),
        req.typed_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.external_handle.as_slice()),
        &req.enc_key,
    )?;

    let response_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    // Read back off the binding rather than from the request: a value that failed validation has no
    // path to signcryption.
    Ok(Some((
        binding.compute_link(),
        SigncryptionReceiver::Solana(*binding.receiver_id()),
        response_domain,
    )))
}

/// An allow-list of one: the Solana path pins its transport key to ML-KEM-512. Deserialization
/// already rejects ML-KEM-1024 on every path, so today this cannot fire — it is defense-in-depth
/// for the day deserialization admits another variant again. Deliberately not a match on the other
/// variants: a future variant should have to be admitted here explicitly rather than inherited.
fn require_mlkem512_transport_key(
    transport_key: &UnifiedPublicEncKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !matches!(transport_key, UnifiedPublicEncKey::MlKem512(_)) {
        return Err(
            anyhow::anyhow!("Solana user decryption requires an ML-KEM-512 transport key").into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod adapter_tests {
    use super::validate_solana_request;
    use crate::consts::SAFE_SER_SIZE_LIMIT;
    use crate::cryptography::encryption::{
        Encryption, PkeScheme, PkeSchemeType, PublicEncKey, UnifiedPublicEncKey,
    };
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{RequestId, TypedCiphertext, UserDecryptionRequest},
        rpc_types::{SigncryptionReceiver, alloy_to_protobuf_domain},
        solana_binding::SolanaUserDecryptBinding,
    };
    use rand::SeedableRng;

    const CHAIN_ID: u64 = (1 << 63) | 12_345;
    const PUBKEY: [u8; 32] = [0x11; 32];
    const PROGRAM_ID: [u8; 32] = [0x22; 32];
    const CONTEXT_ID: [u8; 32] = [0x44; 32];
    const EPOCH_ID: [u8; 32] = [0x55; 32];

    fn request_id(bytes: [u8; 32]) -> RequestId {
        RequestId {
            request_id: alloy_primitives::hex::encode(bytes),
        }
    }

    fn handle(discriminator: u8) -> Vec<u8> {
        let mut handle = [discriminator; 32];
        handle[22..30].copy_from_slice(&CHAIN_ID.to_be_bytes());
        handle.to_vec()
    }

    /// A serialized ML-KEM-512 key, in the form the request carries it.
    fn transport_key() -> Vec<u8> {
        let mut rng = AesRng::seed_from_u64(0);
        let (_sk, pk) = Encryption::new(PkeSchemeType::MlKem512, &mut rng)
            .keygen()
            .expect("keygen");

        let mut buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&pk, &mut buf, SAFE_SER_SIZE_LIMIT)
            .expect("serialize");
        buf
    }

    /// A canonical Solana user-decryption request; every test below changes one field of it.
    fn solana_request() -> UserDecryptionRequest {
        UserDecryptionRequest {
            request_id: Some(request_id([0x01; 32])),
            typed_ciphertexts: vec![
                TypedCiphertext {
                    ciphertext: vec![],
                    fhe_type: 0,
                    external_handle: handle(0xa1),
                    ciphertext_format: 0,
                },
                TypedCiphertext {
                    ciphertext: vec![],
                    fhe_type: 0,
                    external_handle: handle(0xa2),
                    ciphertext_format: 0,
                },
            ],
            key_id: Some(request_id([0x02; 32])),
            client_address: String::new(),
            enc_key: transport_key(),
            domain: Some(
                alloy_to_protobuf_domain(&crate::dummy_domain()).expect("the standard test domain"),
            ),
            extra_data: vec![],
            context_id: Some(request_id(CONTEXT_ID)),
            epoch_id: Some(request_id(EPOCH_ID)),
            solana_pubkey: Some(PUBKEY.to_vec()),
            solana_verifying_program_id: Some(PROGRAM_ID.to_vec()),
            // Empty: the Solana path is authenticated by the legacy scalar signature fields, and
            // scheme selection is orthogonal to who the result is sealed to.
            signing_schemes: vec![],
        }
    }

    fn link_of(req: &UserDecryptionRequest) -> Vec<u8> {
        validate_solana_request(req)
            .expect("a canonical Solana request validates")
            .expect("a Solana request is not left to the EVM path")
            .0
    }

    fn error_of(req: &UserDecryptionRequest) -> String {
        validate_solana_request(req).unwrap_err().to_string()
    }

    #[test]
    fn an_evm_request_is_left_to_the_evm_path() {
        // The adapter's first duty is to not exist for EVM traffic.
        let mut evm = solana_request();
        evm.solana_pubkey = None;
        evm.solana_verifying_program_id = None;
        evm.client_address = "0xdadB0d80178819F2319190D340ce9A924f783711".to_string();

        assert!(validate_solana_request(&evm).expect("no error").is_none());
    }

    #[test]
    fn a_canonical_solana_request_validates() {
        let (link, receiver, _domain) = validate_solana_request(&solana_request())
            .expect("no error")
            .expect("a Solana request");

        assert_eq!(link.len(), 32);
        assert_eq!(receiver, SigncryptionReceiver::Solana(PUBKEY));
    }

    #[test]
    fn the_link_equals_the_canonical_bindings_link() {
        // One canonical binding function: the adapter must not carry a second construction that
        // merely agrees today. If this test can be satisfied without calling the binding, the
        // property it is meant to protect is already gone.
        let req = solana_request();

        let binding = SolanaUserDecryptBinding::new(
            &PROGRAM_ID,
            &PUBKEY,
            &CONTEXT_ID,
            &EPOCH_ID,
            req.typed_ciphertexts
                .iter()
                .map(|ciphertext| ciphertext.external_handle.as_slice()),
            &req.enc_key,
        )
        .expect("canonical");

        assert_eq!(link_of(&req), binding.compute_link());
    }

    #[test]
    fn the_recipient_is_the_typed_pubkey_unchanged() {
        let (_link, receiver, _domain) = validate_solana_request(&solana_request())
            .expect("no error")
            .expect("a Solana request");

        assert_eq!(receiver.as_bytes(), PUBKEY.as_slice());
        assert_eq!(
            receiver.as_bytes().len(),
            32,
            "the recipient reaches signcryption as the key itself, not a 20-byte derivative",
        );
    }

    #[test]
    fn a_legacy_string_identity_alongside_the_typed_field_is_rejected() {
        // Migration rule: while both a legacy string identity and the typed field can appear, a
        // request carrying both is ambiguous about who the recipient is, and guessing is how the
        // result gets sealed to the wrong party.
        for legacy in [
            "0xdadB0d80178819F2319190D340ce9A924f783711".to_string(),
            format!("solana:{}", alloy_primitives::hex::encode(PUBKEY)),
        ] {
            let mut ambiguous = solana_request();
            ambiguous.client_address = legacy;

            assert!(
                error_of(&ambiguous).contains("client_address"),
                "a request with two identities must name the conflict",
            );
        }
    }

    #[test]
    fn an_identity_of_the_wrong_width_is_rejected() {
        for width in [20usize, 31, 33] {
            let mut wrong = solana_request();
            wrong.solana_pubkey = Some(vec![0x11; width]);

            assert!(
                error_of(&wrong).contains("32"),
                "a {width}-byte identity must be rejected by width",
            );
        }
    }

    #[test]
    fn a_request_without_the_program_id_is_rejected() {
        // Half the deployment domain: without it the link would commit to a deployment the
        // request never named, and a permit signed for one program would answer for another.
        let mut missing = solana_request();
        missing.solana_verifying_program_id = None;

        assert!(!error_of(&missing).is_empty());
    }

    #[test]
    fn a_program_id_without_the_pubkey_is_rejected() {
        // The mirror of the missing-program-id case: a request carrying the other Solana field
        // without the identity is contradictory, and must fail here rather than be silently
        // reinterpreted as EVM traffic with the field ignored.
        let mut contradictory = solana_request();
        contradictory.solana_pubkey = None;
        contradictory.client_address = "0xdadB0d80178819F2319190D340ce9A924f783711".to_string();

        assert!(
            error_of(&contradictory).contains("solana_verifying_program_id"),
            "the rejection must name the field that made the request contradictory",
        );
    }

    #[test]
    fn a_program_id_of_the_wrong_width_is_rejected() {
        for width in [20usize, 31, 33] {
            let mut wrong = solana_request();
            wrong.solana_verifying_program_id = Some(vec![0x22; width]);

            assert!(!error_of(&wrong).is_empty(), "width {width}");
        }
    }

    #[test]
    fn the_context_and_epoch_come_from_the_typed_fields() {
        // They are what selected the keys that produced the result, so the link must move when
        // they do.
        let canonical = link_of(&solana_request());

        let mut other_context = solana_request();
        other_context.context_id = Some(request_id([0x66; 32]));

        let mut other_epoch = solana_request();
        other_epoch.epoch_id = Some(request_id([0x77; 32]));

        assert_ne!(canonical, link_of(&other_context));
        assert_ne!(canonical, link_of(&other_epoch));
        assert_ne!(link_of(&other_context), link_of(&other_epoch));
    }

    #[test]
    fn extra_data_is_never_parsed() {
        // The KMS is agnostic to `extra_data` content by design, and the Solana path does not get
        // its own stricter copy of that rule: the connector parses the signed container and
        // forwards the typed values. A second parser here would be a second authority on what the
        // wallet signed, disagreeing with the first at the worst possible moment.
        let canonical = link_of(&solana_request());

        for extra_data in [
            vec![],
            vec![0x00],
            vec![0x02; 65],
            vec![0xff; 3],
            b"not a container at all".to_vec(),
        ] {
            let mut variant = solana_request();
            variant.extra_data = extra_data.clone();

            assert_eq!(
                link_of(&variant),
                canonical,
                "extra_data {extra_data:?} changed the link",
            );
        }
    }

    #[test]
    fn an_mlkem1024_transport_key_is_rejected() {
        // The gate is exercised with an already-deserialized key on purpose: on the request path,
        // deserialization rejects ML-KEM-1024 first, so feeding serialized bytes through the
        // adapter would pass no matter what the allow-list does. Handing the variant to the gate
        // directly is what pins the branch itself.
        use super::require_mlkem512_transport_key;
        use ml_kem::KemCore;

        let mut rng = AesRng::seed_from_u64(0);
        let (_dk, ek) = ml_kem::MlKem1024::generate(&mut rng);
        #[allow(deprecated)]
        let key = UnifiedPublicEncKey::MlKem1024(PublicEncKey(ek));

        let error = require_mlkem512_transport_key(&key)
            .expect_err("the allow-list must reject a non-512 variant")
            .to_string();

        assert!(
            error.contains("requires an ML-KEM-512 transport key"),
            "the rejection must come from the allow-list, got: {error}",
        );
    }

    #[test]
    fn an_unparseable_transport_key_is_rejected() {
        let mut wrong = solana_request();
        wrong.enc_key = b"not a key".to_vec();

        assert!(!error_of(&wrong).is_empty());
    }

    #[test]
    fn handle_validation_is_the_bindings_and_not_a_second_copy() {
        // The adapter must not re-check what the binding checks; it must fail because the binding
        // failed. These are the retained backstops, exercised through the adapter.
        let mut evm_kind = solana_request();
        evm_kind.typed_ciphertexts[0].external_handle[22..30]
            .copy_from_slice(&12_345u64.to_be_bytes());
        assert!(!error_of(&evm_kind).is_empty(), "chain-kind bit");

        let mut mixed = solana_request();
        mixed.typed_ciphertexts[1].external_handle[22..30]
            .copy_from_slice(&(CHAIN_ID + 1).to_be_bytes());
        assert!(!error_of(&mixed).is_empty(), "mixed embedded chain ids");

        let mut short = solana_request();
        short.typed_ciphertexts[0].external_handle.pop();
        assert!(!error_of(&short).is_empty(), "handle width");

        let mut empty = solana_request();
        empty.typed_ciphertexts.clear();
        assert!(!error_of(&empty).is_empty(), "empty handle list");
    }

    #[test]
    fn the_response_domain_is_carried_through_unchanged() {
        // The Solana path does not invent a response domain: the gateway domain the connector
        // configured is what the response signature is produced under, exactly as on the EVM path.
        let (_link, _receiver, domain) = validate_solana_request(&solana_request())
            .expect("no error")
            .expect("a Solana request");

        assert_eq!(domain, crate::dummy_domain());
    }
}
