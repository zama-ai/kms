use std::collections::HashSet;

use alloy_dyn_abi::Eip712Domain;
use kms_grpc::{
    kms::v1::{
        DecryptionRequest, DecryptionResponse, DecryptionResponsePayload, ReencryptionRequest,
        RequestId, TypedCiphertext,
    },
    rpc_types::{protobuf_to_alloy_domain_option, MetaResponse},
};
use tonic::Status;

use crate::{
    anyhow_error_and_log, anyhow_error_and_warn_log,
    cryptography::{
        internal_crypto_types::{PublicEncKey, PublicSigKey, Signature},
        signcryption::internal_verify_sig,
    },
    engine::{base::BaseKmsStruct, traits::BaseKms},
    tonic_handle_potential_err, tonic_some_or_err,
};

const ERR_VALIDATE_DECRYPTION_NO_REQ_ID: &str = "Request ID is not set in decryption request";
const ERR_VALIDATE_DECRYPTION_NO_KEY_ID: &str = "Key ID is not set in decryption request";
const ERR_VALIDATE_DECRYPTION_BAD_REQ_ID: &str = "Request ID is invalid in decryption request";
const ERR_VALIDATE_DECRYPTION_EMPTY_CTS: &str = "No ciphertexts in decryption request";
const ERR_VALIDATE_DECRYPTION_INVALID_AGG_RESP: &str =
    "Could not validate the aggregated responses";
const ERR_VALIDATE_DECRYPTION_NOT_ENOUGH_RESP: &str =
    "Not enough correct responses to decrypt the data!";
const ERR_VALIDATE_DECRYPTION_BAD_CT_COUNT: &str =
    "The number of ciphertexts in the decryption response is wrong";
const ERR_VALIDATE_DECRYPTION_BAD_LINK: &str =
    "The decryption response is not linked to the correct request";
const ERR_VALIDATE_DECRYPTION_EMPTY_REQUEST: &str =
    "Request is None while validating decryption responses";

const ERR_VALIDATE_REENCRYPTION_NO_REQ_ID: &str = "Request ID is not set in reencryption request";
const ERR_VALIDATE_REENCRYPTION_NO_KEY_ID: &str = "Key ID is not set in reencryption request";
const ERR_VALIDATE_REENCRYPTION_BAD_REQ_ID: &str = "Request ID is invalid in reencryption request";
const ERR_VALIDATE_REENCRYPTION_EMPTY_CTS: &str = "No ciphertexts in reencryption request";

/// Validates a request ID and returns an appropriate tonic error if it is invalid.
pub(crate) fn validate_request_id(request_id: &RequestId) -> Result<(), Status> {
    if !request_id.is_valid() {
        tracing::warn!(
            "The value {} is not a valid request ID!",
            request_id.to_string()
        );
        return Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            format!("The value {} is not a valid request ID!", request_id),
        ));
    }
    Ok(())
}

/// Validates a reencryption request and returns ciphertext, FheType, request digest, client
/// encryption key, client verification key, key_id and request_id if valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub fn validate_reencrypt_req(
    req: &ReencryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    Vec<u8>,
    PublicEncKey,
    alloy_primitives::Address,
    RequestId,
    RequestId,
    alloy_sol_types::Eip712Domain,
)> {
    let key_id = tonic_some_or_err(
        req.key_id.clone(),
        format!(
            "{} (Request ID: {:?})",
            ERR_VALIDATE_REENCRYPTION_NO_KEY_ID, req
        ),
    )?;

    let request_id = tonic_some_or_err(
        req.request_id.clone(),
        ERR_VALIDATE_REENCRYPTION_NO_REQ_ID.to_string(),
    )?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "{} (Request ID: {})",
            ERR_VALIDATE_REENCRYPTION_BAD_REQ_ID, request_id
        )));
    }

    if req.typed_ciphertexts.is_empty() {
        return Err(anyhow_error_and_warn_log(format!(
            "{} (Request ID: {})",
            ERR_VALIDATE_REENCRYPTION_EMPTY_CTS, request_id
        )));
    }

    let client_verf_key = alloy_primitives::Address::parse_checksummed(&req.client_address, None)
        .map_err(|e| {
        anyhow::anyhow!(
            "Error parsing checksummed client address: {} - {e}",
            &req.client_address,
        )
    })?;

    let domain = match verify_reencryption_eip712(req) {
        Ok(domain) => {
            tracing::debug!("🔒 Signature verified successfully");
            domain
        }
        Err(e) => {
            return Err(anyhow_error_and_log(format!(
                "Signature verification failed with error {e} for request: {req:?}"
            )));
        }
    };

    let (link, _) = req.compute_link_checked()?;
    let client_enc_key: PublicEncKey = bincode::deserialize(&req.enc_key)?;
    Ok((
        req.typed_ciphertexts.clone(),
        link,
        client_enc_key,
        client_verf_key,
        key_id,
        request_id,
        domain,
    ))
}

/// Validates a decryption request and unpacks and returns
/// the ciphertext, FheType, digest, key_id and request_id if it is valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub(crate) fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    Vec<u8>,
    RequestId,
    RequestId,
    Option<Eip712Domain>,
)> {
    let key_id = tonic_some_or_err(
        req.key_id.clone(),
        format!(
            "{} (Request ID: {:?})",
            ERR_VALIDATE_DECRYPTION_NO_KEY_ID, req
        ),
    )?;

    let request_id = tonic_some_or_err(
        req.request_id.clone(),
        ERR_VALIDATE_DECRYPTION_NO_REQ_ID.to_string(),
    )?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "{} (Request ID: {})",
            ERR_VALIDATE_DECRYPTION_BAD_REQ_ID, request_id
        )));
    }

    if req.ciphertexts.is_empty() {
        return Err(anyhow_error_and_warn_log(format!(
            "{} (Request ID: {})",
            ERR_VALIDATE_DECRYPTION_EMPTY_CTS, request_id
        )));
    }

    let serialized_req = tonic_handle_potential_err(
        bincode::serialize(&req),
        format!("Could not serialize payload {:?}", req),
    )?;
    let req_digest = tonic_handle_potential_err(
        BaseKmsStruct::digest(&serialized_req),
        format!("Could not hash payload {:?}", req),
    )?;

    let eip712_domain = protobuf_to_alloy_domain_option(req.domain.as_ref());

    Ok((
        req.ciphertexts.clone(),
        req_digest,
        key_id,
        request_id,
        eip712_domain,
    ))
}

/// Verify the EIP-712 encoded payload in the request.
pub(crate) fn verify_reencryption_eip712(
    request: &ReencryptionRequest,
) -> anyhow::Result<alloy_sol_types::Eip712Domain> {
    let (_, domain) = request.compute_link_checked()?;
    Ok(domain)
}

/// This function checks that the digest in [other_resp] matches [pivot_resp],
/// [other_resp] contains one of the valid [server_pks] and the signature
/// is correct with respect to this key.
pub(crate) fn validate_dec_meta_data<T: MetaResponse + serde::Serialize>(
    server_pks: &[PublicSigKey],
    pivot_resp: &T,
    other_resp: &T,
    signature: &[u8],
) -> anyhow::Result<bool> {
    if pivot_resp.digest() != other_resp.digest() {
        tracing::warn!(
                    "Response from server with verification key {:?} gave digest {:?}, whereas the pivot server gave digest {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.digest(),
                    other_resp.digest(),
                    other_resp.verification_key()
                );
        return Ok(false);
    }
    let resp_verf_key: PublicSigKey = bincode::deserialize(other_resp.verification_key())?;
    if !server_pks.contains(&resp_verf_key) {
        tracing::warn!("Server key is unknown or incorrect.");
        return Ok(false);
    }

    let sig = Signature {
        sig: k256::ecdsa::Signature::from_slice(signature)?,
    };

    // NOTE that we cannot use `BaseKmsStruct::verify_sig`
    // because `BaseKmsStruct` cannot be compiled for wasm (it has an async mutex).
    if internal_verify_sig(&bincode::serialize(&other_resp)?, &sig, &resp_verf_key).is_err() {
        tracing::warn!("Signature on received response is not valid!");
        return Ok(false);
    }
    Ok(true)
}

/// Pick the pivot as the first response and call [validate_dec_meta_data]
/// on every response. Additionally, ensure that verification keys are unique.
///
/// TODO: we should pick a pivot where t + 1 parties agree on.
pub(crate) fn validate_dec_responses(
    server_pks: &[PublicSigKey],
    agg_resp: &[DecryptionResponse],
) -> anyhow::Result<Option<Vec<DecryptionResponsePayload>>> {
    if agg_resp.is_empty() {
        tracing::warn!("There are no decryption responses!");
        return Ok(None);
    }
    // Pick a pivot response
    let mut option_pivot_payload: Option<DecryptionResponsePayload> = None;
    let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.len());
    let mut verification_keys = HashSet::new();
    for cur_resp in agg_resp {
        let cur_payload = match &cur_resp.payload {
            Some(cur_payload) => cur_payload,
            None => {
                tracing::warn!("No payload in current response from server!");
                continue;
            }
        };

        // Set the first existing element as pivot
        // NOTE: this is the optimistic case where the pivot cannot be wrong
        let pivot_payload = match &option_pivot_payload {
            Some(pivot_payload) => pivot_payload,
            None => {
                // need to clone here because `option_pivot_payload` is larger scope
                option_pivot_payload = Some(cur_payload.clone());
                cur_payload
            }
        };

        // check the uniqueness of verification key
        if verification_keys.contains(&cur_payload.verification_key) {
            tracing::warn!(
                "At least two servers gave the same verification key {}",
                hex::encode(&cur_payload.verification_key),
            );
            continue;
        }

        // Validate that all the responses agree with the pivot on the static parts of the
        // response
        if !validate_dec_meta_data(server_pks, pivot_payload, cur_payload, &cur_resp.signature)? {
            tracing::warn!("Some server did not provide the proper response!");
            continue;
        }

        if pivot_payload.plaintexts.len() != cur_payload.plaintexts.len() {
            tracing::warn!("Plaintext count mismatch!");
            continue;
        }

        // add the verified response
        verification_keys.insert(cur_payload.verification_key.clone());
        resp_parsed_payloads.push(cur_payload.clone());
    }
    Ok(Some(resp_parsed_payloads))
}

/// Validates the aggregated decryption response by checking:
/// - The responses agree on metadata like shares needed
/// - Signatures on responses are valid
/// - That at least [min_agree_count] agree on the same payload
///
/// In addition, if the original request is provided:
/// - The response matches the original request
pub(crate) fn validate_dec_responses_against_request(
    server_pks: &[PublicSigKey],
    request: Option<DecryptionRequest>,
    agg_resp: &[DecryptionResponse],
    min_agree_count: u32,
) -> anyhow::Result<()> {
    let resp_parsed_payloads = crate::some_or_err(
        validate_dec_responses(server_pks, agg_resp)?,
        ERR_VALIDATE_DECRYPTION_INVALID_AGG_RESP.to_string(),
    )?;
    if resp_parsed_payloads.len() < min_agree_count as usize {
        return Err(anyhow_error_and_log(
            ERR_VALIDATE_DECRYPTION_NOT_ENOUGH_RESP,
        ));
    }
    match request {
        Some(req) => {
            let pivot_payload = resp_parsed_payloads[0].clone();
            // if req.fhe_type() != pivot_payload.fhe_type()? {
            //     tracing::warn!("Fhe type in the decryption response is incorrect");
            //     return Ok(false);
            // } //TODO check fhe type?

            if req.ciphertexts.len() != pivot_payload.plaintexts.len() {
                return Err(anyhow_error_and_log(ERR_VALIDATE_DECRYPTION_BAD_CT_COUNT));
            }

            if BaseKmsStruct::digest(&bincode::serialize(&req)?)? != pivot_payload.digest {
                return Err(anyhow_error_and_log(ERR_VALIDATE_DECRYPTION_BAD_LINK));
            }
            Ok(())
        }
        None => {
            tracing::warn!(ERR_VALIDATE_DECRYPTION_EMPTY_REQUEST);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{
            DecryptionRequest, DecryptionResponse, DecryptionResponsePayload, ReencryptionRequest,
            RequestId, TypedCiphertext, TypedPlaintext,
        },
        rpc_types::{alloy_to_protobuf_domain, serialize_hash_element, MetaResponse, ID_LENGTH},
    };
    use rand::SeedableRng;

    use crate::{
        cryptography::signcryption::ephemeral_encryption_key_generation,
        engine::{
            base::gen_sig_keys,
            validation::{
                validate_reencrypt_req, ERR_VALIDATE_DECRYPTION_BAD_CT_COUNT,
                ERR_VALIDATE_DECRYPTION_BAD_LINK, ERR_VALIDATE_DECRYPTION_BAD_REQ_ID,
                ERR_VALIDATE_DECRYPTION_EMPTY_CTS, ERR_VALIDATE_DECRYPTION_INVALID_AGG_RESP,
                ERR_VALIDATE_DECRYPTION_NOT_ENOUGH_RESP, ERR_VALIDATE_DECRYPTION_NO_KEY_ID,
                ERR_VALIDATE_DECRYPTION_NO_REQ_ID, ERR_VALIDATE_REENCRYPTION_BAD_REQ_ID,
                ERR_VALIDATE_REENCRYPTION_EMPTY_CTS, ERR_VALIDATE_REENCRYPTION_NO_KEY_ID,
                ERR_VALIDATE_REENCRYPTION_NO_REQ_ID,
            },
        },
    };

    use super::{
        validate_dec_meta_data, validate_dec_responses, validate_dec_responses_against_request,
        validate_decrypt_req, validate_request_id, verify_reencryption_eip712,
    };

    #[test]
    fn test_validate_decryption_req() {
        // setup data we're going to use in this test
        let alloy_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let request_id = RequestId::derive("request_id").unwrap();
        let key_id = RequestId::derive("key_id").unwrap();

        // ciphertexts are not directly verified except the length
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];

        // empty key ID
        {
            let req = DecryptionRequest {
                request_id: Some(request_id.clone()),
                ciphertexts: ciphertexts.clone(),
                key_id: None,
                domain: Some(domain.clone()),
            };
            assert!(validate_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_DECRYPTION_NO_KEY_ID));
        }

        // empty request ID
        {
            let req = DecryptionRequest {
                request_id: None,
                ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
            };
            assert!(validate_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_DECRYPTION_NO_REQ_ID));
        }

        // invalid request ID
        {
            let bad_req_id = RequestId {
                request_id: ['x'; ID_LENGTH].iter().collect(),
            };
            let req = DecryptionRequest {
                request_id: Some(bad_req_id),
                ciphertexts: vec![],
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
            };
            assert!(validate_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_DECRYPTION_BAD_REQ_ID));
        }

        // empty ciphertext
        {
            let req = DecryptionRequest {
                request_id: Some(request_id.clone()),
                ciphertexts: vec![],
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
            };
            assert!(validate_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_DECRYPTION_EMPTY_CTS));
        }

        // finally everything is ok
        {
            let req = DecryptionRequest {
                request_id: Some(request_id.clone()),
                ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
            };
            let (_, _, _, _, domain) = validate_decrypt_req(&req).unwrap();
            assert!(domain.is_some());
        }
    }

    #[test]
    fn test_validate_reencryption_req() {
        // setup data we're going to use in this test
        let alloy_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let request_id = RequestId::derive("request_id").unwrap();
        let key_id = RequestId::derive("key_id").unwrap();
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let mut rng = AesRng::from_random_seed();
        let (enc_pk, _enc_sk) = ephemeral_encryption_key_generation(&mut rng);
        let enc_pk_buf = bincode::serialize(&enc_pk).unwrap();

        // ciphertexts are not directly verified except the length
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];

        // empty key ID
        {
            let req = ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: None,
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_reencrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_REENCRYPTION_NO_KEY_ID));
        }

        // empty request ID
        {
            let req = ReencryptionRequest {
                request_id: None,
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_reencrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_REENCRYPTION_NO_REQ_ID));
        }

        // invalid request ID
        {
            let bad_req_id = RequestId {
                request_id: ['x'; ID_LENGTH].iter().collect(),
            };
            let req = ReencryptionRequest {
                request_id: Some(bad_req_id),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_reencrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_REENCRYPTION_BAD_REQ_ID));
        }

        // empty ciphertext
        {
            let req = ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_reencrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_REENCRYPTION_EMPTY_CTS));
        }

        // bad client address
        {
            let req = ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(Some(1)),
                enc_key: enc_pk_buf.clone(),
            };
            assert_eq!(
                "Error parsing checksummed client address: 0xD8Da6bf26964Af9d7EEd9e03e53415d37AA96045 - Bad address checksum",
                validate_reencrypt_req(&req).unwrap_err().to_string()
            );
        }

        // bad public key
        {
            let mut bad_enc_pk_buf = enc_pk_buf.clone();
            bad_enc_pk_buf[0] ^= 1;
            let req = ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: bad_enc_pk_buf,
            };
            assert!(validate_reencrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains("io error"));
        }

        // finally everything is ok
        {
            let req = ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_reencrypt_req(&req).is_ok());
        }
    }

    #[test]
    fn test_validate_request_id() {
        // not hex
        let bad_req_id1 = RequestId {
            request_id: ['x'; ID_LENGTH].iter().collect(),
        };
        assert!(validate_request_id(&bad_req_id1).is_err());

        // wrong length
        let bad_req_id2 = RequestId {
            request_id: ['a'; ID_LENGTH - 1].iter().collect(),
        };
        assert!(validate_request_id(&bad_req_id2).is_err());

        let good_req_id = RequestId {
            request_id: ['a'; ID_LENGTH].iter().collect(),
        };
        assert!(validate_request_id(&good_req_id).is_err());
    }

    #[test]
    fn test_verify_reenc_eip712() {
        let mut rng = AesRng::from_random_seed();
        let (client_pk, _client_sk) = gen_sig_keys(&mut rng);
        let client_address = alloy_primitives::Address::from_public_key(client_pk.pk());
        let ciphertext = vec![1, 2, 3];
        let (enc_pk, _) = ephemeral_encryption_key_generation(&mut rng);
        let key_id = RequestId::derive("key_id").unwrap();

        let typed_ciphertext = TypedCiphertext {
            ciphertext,
            fhe_type: 1,
            ciphertext_format: 0,
            external_handle: vec![123],
        };
        let domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain_msg = alloy_to_protobuf_domain(&domain).unwrap();

        let req = kms_grpc::kms::v1::ReencryptionRequest {
            request_id: Some(RequestId {
                request_id: "dummy request ID".to_owned(),
            }),
            enc_key: bincode::serialize(&enc_pk).unwrap(),
            client_address: client_address.to_checksum(None),
            key_id: Some(key_id),
            typed_ciphertexts: vec![typed_ciphertext],
            domain: Some(domain_msg),
        };

        {
            // happy path
            verify_reencryption_eip712(&req).unwrap();
        }
        {
            // use a wrong client address (invalid string length)
            let mut bad_req = req.clone();
            bad_req.client_address = "66f9664f97F2b50F62D13eA064982f936dE76657".to_string();
            match verify_reencryption_eip712(&bad_req) {
                Ok(_) => panic!("expected failure"),
                Err(e) => {
                    assert_eq!(e.to_string(), "error parsing checksummed address: 66f9664f97F2b50F62D13eA064982f936dE76657 - invalid string length");
                }
            }
        }
        {
            // use the same address for verifying contract and client address should fail
            // we don't explicitly test the error string, it is tested in the grpc crate
            let mut bad_domain = domain.clone();
            bad_domain.verifying_contract = Some(client_address);
            let mut bad_req = req.clone();
            bad_req.domain = Some(alloy_to_protobuf_domain(&bad_domain).unwrap());
            match verify_reencryption_eip712(&bad_req) {
                Ok(_) => panic!("expected failure"),
                Err(_e) => {}
            }
        }
    }

    #[derive(serde::Serialize)]
    struct DummyDecValue {
        verification_key: Vec<u8>,
        digest: Vec<u8>,
    }

    impl MetaResponse for DummyDecValue {
        fn verification_key(&self) -> &[u8] {
            &self.verification_key
        }

        fn digest(&self) -> &[u8] {
            &self.digest
        }
    }

    #[test]
    fn test_validate_dec_meta_response() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = [vk0, vk1, vk2];

        let pivot = DummyDecValue {
            verification_key: bincode::serialize(&pks[0]).unwrap(),
            digest: vec![1, 2, 3, 4],
        };

        let pivot_buf = bincode::serialize(&pivot).unwrap();

        // use a bad signature (signed with wrong private key)
        {
            let signature = &crate::cryptography::signcryption::sign(&pivot_buf, &sk1).unwrap();
            let signature_buf = signature.sig.to_vec();

            assert!(!validate_dec_meta_data(&pks, &pivot, &pivot, &signature_buf).unwrap());
        }

        // use a bad signature (malformed signature)
        {
            let signature = &crate::cryptography::signcryption::sign(&pivot_buf, &sk0).unwrap();
            // The signature is malformed because it's using bincode to serialize instead of `signature.sig.to_vec()`.
            let signature_buf = bincode::serialize(&signature).unwrap();

            assert!(validate_dec_meta_data(&pks, &pivot, &pivot, &signature_buf).is_err());
        }

        // use a bad signature (signing the wrong value)
        {
            let bad_value = DummyDecValue {
                verification_key: bincode::serialize(&pks[0]).unwrap(),
                digest: vec![1, 2, 3, 4, 5], // Original digest does not contain the 5
            };
            let bad_value_buf = bincode::serialize(&bad_value).unwrap();

            let bad_signature =
                &crate::cryptography::signcryption::sign(&bad_value_buf, &sk0).unwrap();
            let bad_signature_buf = bad_signature.sig.to_vec();

            assert!(!validate_dec_meta_data(&pks, &pivot, &pivot, &bad_signature_buf).unwrap());
        }

        // use a bad response (digest mismatch)
        {
            let bad_value = DummyDecValue {
                verification_key: bincode::serialize(&pks[0]).unwrap(),
                digest: vec![1, 2, 3, 4, 5], // Original digest does not contain the 5
            };
            let bad_value_buf = bincode::serialize(&bad_value).unwrap();

            let signature = &crate::cryptography::signcryption::sign(&bad_value_buf, &sk0).unwrap();
            let signature_buf = signature.sig.to_vec();

            assert!(!validate_dec_meta_data(&pks, &pivot, &bad_value, &signature_buf).unwrap());
        }

        // use a bad response (bad validation key)
        {
            let (vk, _sk0) = gen_sig_keys(&mut rng);
            let bad_value = DummyDecValue {
                verification_key: bincode::serialize(&vk).unwrap(),
                digest: vec![1, 2, 3, 4],
            };
            let bad_value_buf = bincode::serialize(&bad_value).unwrap();

            let signature = &crate::cryptography::signcryption::sign(&bad_value_buf, &sk0).unwrap();
            let signature_buf = signature.sig.to_vec();

            assert!(!validate_dec_meta_data(&pks, &pivot, &bad_value, &signature_buf).unwrap());
        }

        // happy path
        {
            let signature = &crate::cryptography::signcryption::sign(&pivot_buf, &sk0).unwrap();
            let signature_buf = signature.sig.to_vec(); // NOTE: signatures are not serialized with bincode

            assert!(validate_dec_meta_data(&pks, &pivot, &pivot, &signature_buf).unwrap());
        }
    }

    #[test]
    fn test_validate_dec_responses() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = [vk0, vk1, vk2];

        let resp0 = {
            let payload = DecryptionResponsePayload {
                verification_key: bincode::serialize(&pks[0]).unwrap(),
                digest: vec![1, 2, 3, 4],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
            };
            let payload_buf = bincode::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::sign(&payload_buf, &sk0).unwrap();
            let signature_buf = signature.sig.to_vec();

            DecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };
        let resp1 = {
            let payload = DecryptionResponsePayload {
                verification_key: bincode::serialize(&pks[1]).unwrap(),
                digest: vec![1, 2, 3, 4],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
            };
            let payload_buf = bincode::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::sign(&payload_buf, &sk1).unwrap();
            let signature_buf = signature.sig.to_vec();

            DecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };

        // in this test we just want to test that we can catch a duplicate validation key
        // the other validation such as signatures are performed in `validate_dec_meta_data`

        // using an empty payload, we should only get 1 valid response
        {
            let mut empty_resp = resp1.clone();
            empty_resp.payload = None;
            let mut bad_agg_resp = vec![resp0.clone(), empty_resp];
            assert_eq!(
                validate_dec_responses(&pks, &bad_agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );

            // reverse the aggregate response so the empty one is the first
            bad_agg_resp.reverse();
            assert_eq!(
                validate_dec_responses(&pks, &bad_agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );
        }

        // use the same response twice, we should only get 1 valid response
        {
            let bad_agg_resp = vec![resp0.clone(), resp0.clone()];
            assert_eq!(
                validate_dec_responses(&pks, &bad_agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );
        }

        // if one of the responses have a wrong number of plaintext, we should only get 1 valid response
        {
            let bad_resp = {
                let payload = DecryptionResponsePayload {
                    verification_key: bincode::serialize(&pks[1]).unwrap(),
                    digest: vec![1, 2, 3, 4],
                    plaintexts: vec![
                        TypedPlaintext {
                            bytes: vec![1],
                            fhe_type: 1,
                        },
                        TypedPlaintext {
                            bytes: vec![1],
                            fhe_type: 1,
                        },
                    ],
                    external_signature: Some(vec![]),
                };
                let payload_buf = bincode::serialize(&payload).unwrap();
                let signature =
                    &crate::cryptography::signcryption::sign(&payload_buf, &sk1).unwrap();
                let signature_buf = signature.sig.to_vec();

                DecryptionResponse {
                    signature: signature_buf,
                    payload: Some(payload),
                }
            };
            let agg_resp = vec![resp0.clone(), bad_resp];
            assert_eq!(
                validate_dec_responses(&pks, &agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(
                validate_dec_responses(&pks, &agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                2
            );
        }
    }

    #[test]
    fn test_validate_dec_responses_against_request() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = [vk0, vk1, vk2];

        let request = DecryptionRequest {
            request_id: Some(RequestId::derive("DecryptionRequest").unwrap()),
            ciphertexts: vec![TypedCiphertext {
                ciphertext: vec![1, 2, 3, 4],
                fhe_type: 1,
                external_handle: vec![1, 2, 3, 4],
                ciphertext_format: 1,
            }],
            key_id: Some(RequestId::derive("DecryptionRequest key_id").unwrap()),
            domain: None,
        };

        let digest = serialize_hash_element(&request).unwrap();

        let resp0 = {
            let payload = DecryptionResponsePayload {
                verification_key: bincode::serialize(&pks[0]).unwrap(),
                digest: digest.clone(),
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
            };
            let payload_buf = bincode::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::sign(&payload_buf, &sk0).unwrap();
            let signature_buf = signature.sig.to_vec();

            DecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };
        let resp1 = {
            let payload = DecryptionResponsePayload {
                verification_key: bincode::serialize(&pks[1]).unwrap(),
                digest: digest.clone(),
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
            };
            let payload_buf = bincode::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::sign(&payload_buf, &sk1).unwrap();
            let signature_buf = signature.sig.to_vec();

            DecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };

        // invalid aggregate response, e.g., when there are none
        {
            let agg_resp = vec![];
            assert!(validate_dec_responses_against_request(
                &pks,
                Some(request.clone()),
                &agg_resp,
                1
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_DECRYPTION_INVALID_AGG_RESP));
        }

        // not enough decryption responses
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert!(validate_dec_responses_against_request(
                &pks,
                Some(request.clone()),
                &agg_resp,
                3
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_DECRYPTION_NOT_ENOUGH_RESP));
        }

        // ciphertext count is wrong
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let bad_request = DecryptionRequest {
                request_id: Some(RequestId::derive("DecryptionRequest").unwrap()),
                // here we use two ciphertexts
                ciphertexts: vec![
                    TypedCiphertext {
                        ciphertext: vec![1, 2, 3, 4],
                        fhe_type: 1,
                        external_handle: vec![1, 2, 3, 4],
                        ciphertext_format: 1,
                    },
                    TypedCiphertext {
                        ciphertext: vec![5, 6, 7, 8],
                        fhe_type: 1,
                        external_handle: vec![5, 6, 7, 8],
                        ciphertext_format: 1,
                    },
                ],
                key_id: Some(RequestId::derive("DecryptionRequest key_id").unwrap()),
                domain: None,
            };
            assert!(
                validate_dec_responses_against_request(&pks, Some(bad_request), &agg_resp, 2)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_DECRYPTION_BAD_CT_COUNT)
            );
        }

        // link is wrong
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let bad_request = DecryptionRequest {
                request_id: Some(RequestId::derive("DecryptionRequest").unwrap()),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: vec![1, 2, 3, 4],
                    fhe_type: 2, // we change the fhe_type so it's the wrong request
                    external_handle: vec![1, 2, 3, 4],
                    ciphertext_format: 1,
                }],
                key_id: Some(RequestId::derive("DecryptionRequest key_id").unwrap()),
                domain: None,
            };
            assert!(
                validate_dec_responses_against_request(&pks, Some(bad_request), &agg_resp, 2)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_DECRYPTION_BAD_LINK)
            );
        }

        // request is empty, which should pass
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            validate_dec_responses_against_request(&pks, None, &agg_resp, 2).unwrap();
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            validate_dec_responses_against_request(&pks, Some(request.clone()), &agg_resp, 2)
                .unwrap();
        }
    }
}
