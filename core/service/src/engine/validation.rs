use alloy_dyn_abi::Eip712Domain;
use kms_grpc::{
    kms::v1::{DecryptionRequest, ReencryptionRequest, RequestId, TypedCiphertext},
    rpc_types::protobuf_to_alloy_domain_option,
};
use tonic::Status;

use crate::{
    anyhow_error_and_log, anyhow_error_and_warn_log,
    cryptography::internal_crypto_types::PublicEncKey, engine::base::BaseKmsStruct,
    engine::traits::BaseKms, tonic_handle_potential_err, tonic_some_or_err,
};

const ERR_VALIDATE_DECRYPTION_NO_REQ_ID: &str = "Request ID is not set in decryption request";
const ERR_VALIDATE_DECRYPTION_NO_KEY_ID: &str = "Key ID is not set in decryption request";
const ERR_VALIDATE_DECRYPTION_BAD_REQ_ID: &str = "Request ID is invalid in decryption request";
const ERR_VALIDATE_DECRYPTION_EMPTY_CTS: &str = "No ciphertexts in decryption request";

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

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{DecryptionRequest, ReencryptionRequest, RequestId, TypedCiphertext},
        rpc_types::{alloy_to_protobuf_domain, ID_LENGTH},
    };

    use crate::{
        cryptography::signcryption::ephemeral_encryption_key_generation,
        engine::{
            base::gen_sig_keys,
            validation::{
                validate_reencrypt_req, ERR_VALIDATE_DECRYPTION_BAD_REQ_ID,
                ERR_VALIDATE_DECRYPTION_EMPTY_CTS, ERR_VALIDATE_DECRYPTION_NO_KEY_ID,
                ERR_VALIDATE_DECRYPTION_NO_REQ_ID, ERR_VALIDATE_REENCRYPTION_BAD_REQ_ID,
                ERR_VALIDATE_REENCRYPTION_EMPTY_CTS, ERR_VALIDATE_REENCRYPTION_NO_KEY_ID,
                ERR_VALIDATE_REENCRYPTION_NO_REQ_ID,
            },
        },
    };

    use super::{validate_decrypt_req, validate_request_id, verify_reencryption_eip712};

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
}
