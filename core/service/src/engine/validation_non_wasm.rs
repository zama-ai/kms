use std::collections::{HashMap, HashSet};

use alloy_dyn_abi::Eip712Domain;
use itertools::Itertools;
use kms_grpc::utils::tonic_result::BoxedStatus;
use kms_grpc::RequestId;
use kms_grpc::{
    kms::v1::{
        PublicDecryptionRequest, PublicDecryptionResponse, PublicDecryptionResponsePayload,
        TypedCiphertext, TypedPlaintext, UserDecryptionRequest,
    },
    rpc_types::protobuf_to_alloy_domain_option,
};
use threshold_fhe::hashing::DomainSep;

use crate::cryptography::internal_crypto_types::UnifiedPublicEncKey;
use crate::{
    anyhow_error_and_log, anyhow_error_and_warn_log,
    cryptography::{
        internal_crypto_types::{PublicEncKey, PublicSigKey, Signature},
        signcryption::internal_verify_sig,
    },
    tonic_some_or_err,
};

pub(crate) const DSEP_PUBLIC_DECRYPTION: DomainSep = *b"PUBL_DEC";

const ERR_VALIDATE_PUBLIC_DECRYPTION_NO_REQ_ID: &str =
    "Request ID is not set in public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_NO_KEY_ID: &str =
    "Key ID is not set in public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_REQ_ID: &str =
    "Request ID is invalid in public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_KEY_ID: &str =
    "Key ID is invalid in public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS: &str =
    "No ciphertexts in public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_INVALID_AGG_RESP: &str =
    "Could not validate the aggregated public decryption responses";
const ERR_VALIDATE_PUBLIC_DECRYPTION_NOT_ENOUGH_RESP: &str =
    "Not enough correct public decryption responses to decrypt the data!";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_CT_COUNT: &str =
    "The number of ciphertexts in the public decryption response is wrong";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK: &str =
    "The public decryption response is not linked to the correct public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_MISSING_REQ_ID: &str =
    "Request ID is not set in public decryption response";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE: &str =
    "Plaintext type mismatch in public decryption response";
const ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_REQUEST: &str =
    "Public decryption request is None while validating public decryption responses";

const ERR_VALIDATE_USER_DECRYPTION_NO_REQ_ID: &str =
    "Request ID is not set in user decryption request";
const ERR_VALIDATE_USER_DECRYPTION_NO_KEY_ID: &str = "Key ID is not set in user decryption request";
const ERR_VALIDATE_USER_DECRYPTION_BAD_REQ_ID: &str =
    "Request ID is invalid in user decryption request";
const ERR_VALIDATE_USER_DECRYPTION_BAD_KEY_ID: &str =
    "Key ID is invalid in user decryption request";
const ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS: &str = "No ciphertexts in user decryption request";

/// Validates a request ID and returns an appropriate tonic error if it is invalid.
pub(crate) fn validate_request_id(request_id: &RequestId) -> Result<(), BoxedStatus> {
    if !request_id.is_valid() {
        tracing::warn!(
            "The value {} is not a valid request ID!",
            request_id.to_string()
        );
        return Err(BoxedStatus::from(tonic::Status::new(
            tonic::Code::InvalidArgument,
            format!("Invalid request id: {request_id}"),
        )));
    }
    Ok(())
}

/// Validates a user decryption request and returns ciphertext, FheType, request digest, client
/// encryption key, client verification key, key_id and request_id if valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub fn validate_user_decrypt_req(
    req: &UserDecryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    Vec<u8>,
    UnifiedPublicEncKey,
    alloy_primitives::Address,
    RequestId,
    RequestId,
    alloy_sol_types::Eip712Domain,
)> {
    let key_id: RequestId = tonic_some_or_err(
        req.key_id.clone(),
        format!("{ERR_VALIDATE_USER_DECRYPTION_NO_KEY_ID} (Request ID: {req:?})"),
    )?
    .into();
    if !key_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "{ERR_VALIDATE_USER_DECRYPTION_BAD_KEY_ID} (Request ID: {key_id})"
        )));
    }

    let request_id: RequestId = tonic_some_or_err(
        req.request_id.clone(),
        ERR_VALIDATE_USER_DECRYPTION_NO_REQ_ID.to_string(),
    )?
    .into();
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "{ERR_VALIDATE_USER_DECRYPTION_BAD_REQ_ID} (Request ID: {request_id})"
        )));
    }

    if req.typed_ciphertexts.is_empty() {
        return Err(anyhow_error_and_warn_log(format!(
            "{ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS} (Request ID: {request_id})"
        )));
    }

    let client_verf_key = alloy_primitives::Address::parse_checksummed(&req.client_address, None)
        .map_err(|e| {
        anyhow::anyhow!(
            "Error parsing checksummed client address: {} - {e}",
            &req.client_address,
        )
    })?;

    let domain = match verify_user_decrypt_eip712(req) {
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
    // NOTE: we need to do some backward compatibility support here so
    // first try to deserialize it using the old format
    let client_enc_key = match bc2wrap::deserialize::<PublicEncKey<ml_kem::MlKem1024>>(&req.enc_key)
    {
        Ok(inner) => {
            tracing::warn!("🔒 Using MlKem1024 public encryption key");
            UnifiedPublicEncKey::MlKem1024(inner)
        }
        Err(_) => tfhe::safe_serialization::safe_deserialize::<UnifiedPublicEncKey>(
            std::io::Cursor::new(&req.enc_key),
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Error deserializing UnifiedPublicEncKey from UserDecryptionRequest: {e}"
            )
        })?,
    };
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

/// Validates a public decryption request and unpacks and returns
/// the ciphertext, FheType, digest, key_id and request_id if it is valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub fn validate_public_decrypt_req(
    req: &PublicDecryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    RequestId,
    RequestId,
    Option<Eip712Domain>,
)> {
    let key_id: RequestId = tonic_some_or_err(
        req.key_id.clone(),
        format!("{ERR_VALIDATE_PUBLIC_DECRYPTION_NO_KEY_ID} (Request ID: {req:?})"),
    )?
    .into();
    if !key_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "{ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_KEY_ID} (Request ID: {key_id})"
        )));
    }

    let request_id: RequestId = tonic_some_or_err(
        req.request_id.clone(),
        ERR_VALIDATE_PUBLIC_DECRYPTION_NO_REQ_ID.to_string(),
    )?
    .into();
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "{ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_REQ_ID} (Request ID: {request_id})"
        )));
    }

    if req.ciphertexts.is_empty() {
        return Err(anyhow_error_and_warn_log(format!(
            "{ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS} (Request ID: {request_id})"
        )));
    }

    let eip712_domain = protobuf_to_alloy_domain_option(req.domain.as_ref());

    Ok((req.ciphertexts.clone(), key_id, request_id, eip712_domain))
}

/// Verify the EIP-712 encoded payload in the request.
pub(crate) fn verify_user_decrypt_eip712(
    request: &UserDecryptionRequest,
) -> anyhow::Result<alloy_sol_types::Eip712Domain> {
    let (_, domain) = request.compute_link_checked()?;
    Ok(domain)
}

/// This function checks that the digest in [other_resp] matches [pivot_resp],
/// [other_resp] contains one of the valid [server_pks] and the signature
/// is correct with respect to this key.
fn validate_public_decrypt_meta_data(
    server_pks: &HashMap<u32, PublicSigKey>,
    pivot_resp: &PublicDecryptionResponsePayload,
    other_resp: &PublicDecryptionResponsePayload,
    signature: &[u8],
) -> anyhow::Result<bool> {
    if pivot_resp.request_id != other_resp.request_id {
        tracing::warn!(
                    "Response from server with verification key {:?} gave request ID {:?}, whereas the pivot server gave request ID {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key,
                    pivot_resp.request_id,
                    other_resp.request_id,
                    other_resp.verification_key
                );
        return Ok(false);
    }
    let resp_verf_key: PublicSigKey = bc2wrap::deserialize(&other_resp.verification_key)?;
    if !server_pks.values().contains(&resp_verf_key) {
        tracing::warn!("Server key is unknown or incorrect.");
        return Ok(false);
    }

    // the plaintexts should match
    if pivot_resp.plaintexts != other_resp.plaintexts {
        tracing::warn!("Plaintext does not match the pivot.");
        return Ok(false);
    }

    let sig = Signature {
        sig: k256::ecdsa::Signature::from_slice(signature)?,
    };

    // NOTE that we cannot use `BaseKmsStruct::verify_sig`
    // because `BaseKmsStruct` cannot be compiled for wasm (it has an async mutex).
    if internal_verify_sig(
        &DSEP_PUBLIC_DECRYPTION,
        &bc2wrap::serialize(&other_resp)?,
        &sig,
        &resp_verf_key,
    )
    .is_err()
    {
        tracing::warn!("Signature on received public decryption response is not valid!");
        return Ok(false);
    }
    Ok(true)
}

/// Fields in [PublicDecryptionResponsePayload] that should remain the same
/// for the same request.
#[derive(Hash, PartialEq, Eq)]
struct PublicDecryptionResponseInvariants {
    request_id: Option<RequestId>,
    plaintexts: Vec<TypedPlaintext>,
}

impl From<PublicDecryptionResponsePayload> for PublicDecryptionResponseInvariants {
    fn from(value: PublicDecryptionResponsePayload) -> Self {
        Self {
            request_id: value.request_id.clone().map(|id| id.into()),
            plaintexts: value.plaintexts.clone(),
        }
    }
}

pub(crate) fn select_most_common_public_dec(
    min_occurence: usize,
    agg_resp: &[PublicDecryptionResponse],
) -> Option<PublicDecryptionResponsePayload> {
    let iter = agg_resp.iter().map(|resp| resp.payload.as_ref());
    let idx = crate::engine::validation::select_most_common::<_, PublicDecryptionResponseInvariants>(
        min_occurence,
        iter,
    );
    idx.and_then(|i| agg_resp[i].payload.clone())
}

/// Pick the pivot as the first response and call [validate_dec_meta_data]
/// on every response. Additionally, ensure that verification keys are unique.
fn validate_public_decrypt_responses(
    server_pks: &HashMap<u32, PublicSigKey>,
    agg_resp: &[PublicDecryptionResponse],
) -> anyhow::Result<Option<Vec<PublicDecryptionResponsePayload>>> {
    if agg_resp.is_empty() {
        tracing::warn!("There are no public decryption responses!");
        return Ok(None);
    }
    // Pick a pivot response
    let min_occurence = (server_pks.len() - 1) / 3 + 1; // note that this is floored division
    let pivot_payload = match select_most_common_public_dec(min_occurence, agg_resp) {
        Some(inner) => inner,
        None => anyhow::bail!("Cannot find public decryption pivot"),
    };
    let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.len());
    let mut verification_keys = HashSet::new();
    for cur_resp in agg_resp {
        let cur_payload = match &cur_resp.payload {
            Some(cur_payload) => cur_payload,
            None => {
                tracing::warn!("No payload in current public decryption response from server!");
                continue;
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
        if !validate_public_decrypt_meta_data(
            server_pks,
            &pivot_payload,
            cur_payload,
            &cur_resp.signature,
        )? {
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
pub(crate) fn validate_public_decrypt_responses_against_request(
    server_pks: &HashMap<u32, PublicSigKey>,
    request: Option<PublicDecryptionRequest>,
    agg_resp: &[PublicDecryptionResponse],
    min_agree_count: u32,
) -> anyhow::Result<()> {
    let resp_parsed_payloads = crate::some_or_err(
        validate_public_decrypt_responses(server_pks, agg_resp)?,
        ERR_VALIDATE_PUBLIC_DECRYPTION_INVALID_AGG_RESP.to_string(),
    )?;
    if resp_parsed_payloads.len() < min_agree_count as usize {
        return Err(anyhow_error_and_log(
            ERR_VALIDATE_PUBLIC_DECRYPTION_NOT_ENOUGH_RESP,
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
                return Err(anyhow_error_and_log(
                    ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_CT_COUNT,
                ));
            }

            for (ct, pt) in req
                .ciphertexts
                .iter()
                .zip_eq(pivot_payload.plaintexts.iter())
            {
                if ct.fhe_type != pt.fhe_type {
                    return Err(anyhow_error_and_log(
                        ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE,
                    ));
                }
            }

            match (req.request_id, pivot_payload.request_id) {
                (Some(expected), Some(actual)) => {
                    if expected != actual {
                        return Err(anyhow_error_and_log(
                            ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK,
                        ));
                    }
                }
                _ => {
                    return Err(anyhow_error_and_log(
                        ERR_VALIDATE_PUBLIC_DECRYPTION_MISSING_REQ_ID,
                    ));
                }
            }

            Ok(())
        }
        None => {
            tracing::warn!(ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_REQUEST);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{
            self, PublicDecryptionRequest, PublicDecryptionResponse,
            PublicDecryptionResponsePayload, TypedCiphertext, TypedPlaintext,
            UserDecryptionRequest,
        },
        rpc_types::{alloy_to_protobuf_domain, ID_LENGTH},
    };

    use rand::SeedableRng;

    use crate::{
        cryptography::{
            internal_crypto_types::{gen_sig_keys, UnifiedPublicEncKey},
            signcryption::ephemeral_encryption_key_generation,
        },
        engine::{
            base::derive_request_id,
            validation_non_wasm::{
                select_most_common_public_dec, validate_public_decrypt_responses,
            },
        },
    };

    use super::{
        validate_public_decrypt_meta_data, validate_public_decrypt_req,
        validate_public_decrypt_responses_against_request, validate_request_id,
        validate_user_decrypt_req, verify_user_decrypt_eip712, DSEP_PUBLIC_DECRYPTION,
        ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_CT_COUNT, ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE,
        ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK, ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_REQ_ID,
        ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS, ERR_VALIDATE_PUBLIC_DECRYPTION_INVALID_AGG_RESP,
        ERR_VALIDATE_PUBLIC_DECRYPTION_NOT_ENOUGH_RESP, ERR_VALIDATE_PUBLIC_DECRYPTION_NO_KEY_ID,
        ERR_VALIDATE_PUBLIC_DECRYPTION_NO_REQ_ID, ERR_VALIDATE_USER_DECRYPTION_BAD_REQ_ID,
        ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS, ERR_VALIDATE_USER_DECRYPTION_NO_KEY_ID,
        ERR_VALIDATE_USER_DECRYPTION_NO_REQ_ID,
    };

    #[test]
    fn test_validate_public_decrypt_req() {
        // setup data we're going to use in this test
        let alloy_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let request_id = derive_request_id("request_id").unwrap();
        let key_id = derive_request_id("key_id").unwrap();

        // ciphertexts are not directly verified except the length
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];

        // empty key ID
        {
            let req = PublicDecryptionRequest {
                request_id: Some(request_id.into()),
                ciphertexts: ciphertexts.clone(),
                key_id: None,
                domain: Some(domain.clone()),
            };
            assert!(validate_public_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_NO_KEY_ID));
        }

        // empty request ID
        {
            let req = PublicDecryptionRequest {
                request_id: None,
                ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
            };
            assert!(validate_public_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_NO_REQ_ID));
        }

        // invalid request ID
        {
            let bad_req_id = v1::RequestId {
                request_id: ['x'; ID_LENGTH].iter().collect(),
            };
            let req = PublicDecryptionRequest {
                request_id: Some(bad_req_id),
                ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
            };
            assert!(validate_public_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_REQ_ID));
        }

        // empty ciphertext
        {
            let req = PublicDecryptionRequest {
                request_id: Some(request_id.into()),
                ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
            };
            assert!(validate_public_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS));
        }

        // finally everything is ok
        {
            let req = PublicDecryptionRequest {
                request_id: Some(request_id.into()),
                ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
            };
            let (_, _, _, domain) = validate_public_decrypt_req(&req).unwrap();
            assert!(domain.is_some());
        }
    }

    #[test]
    fn test_validate_user_decrypt_req() {
        // setup data we're going to use in this test
        let alloy_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let request_id = derive_request_id("request_id").unwrap();
        let key_id = derive_request_id("key_id").unwrap();
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let mut rng = AesRng::from_random_seed();
        let (enc_pk, _enc_sk) = ephemeral_encryption_key_generation::<ml_kem::MlKem512>(&mut rng);
        let unified_enc_pk = UnifiedPublicEncKey::MlKem512(enc_pk.clone());

        let mut enc_pk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &unified_enc_pk,
            &mut enc_pk_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        // ciphertexts are not directly verified except the length
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];

        // empty key ID
        {
            let req = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: None,
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_user_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_NO_KEY_ID));
        }

        // empty request ID
        {
            let req = UserDecryptionRequest {
                request_id: None,
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_user_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_NO_REQ_ID));
        }

        // invalid request ID
        {
            let bad_req_id = v1::RequestId {
                request_id: ['x'; ID_LENGTH].iter().collect(),
            };
            let req = UserDecryptionRequest {
                request_id: Some(bad_req_id),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_user_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_BAD_REQ_ID));
        }

        // empty ciphertext
        {
            let req = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_user_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS));
        }

        // bad client address
        {
            let req = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(Some(1)),
                enc_key: enc_pk_buf.clone(),
            };
            assert_eq!(
                "Error parsing checksummed client address: 0xD8Da6bf26964Af9d7EEd9e03e53415d37AA96045 - Bad address checksum",
                validate_user_decrypt_req(&req).unwrap_err().to_string()
            );
        }

        // bad public key
        {
            // note that we're serializing the mlkem512 public key, which is not supported
            let bad_enc_pk_buf = bc2wrap::serialize(&enc_pk).unwrap();
            let req = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: bad_enc_pk_buf,
            };
            assert!(validate_user_decrypt_req(&req)
                .unwrap_err()
                .to_string()
                .contains("Error deserializing")); // the error message that is returned from trying to decode the bad encoding
        }

        // finally everything is ok
        {
            let req = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
            };
            assert!(validate_user_decrypt_req(&req).is_ok());
        }
    }

    #[test]
    fn test_validate_request_id() {
        // not hex
        let bad_req_id1 = v1::RequestId {
            request_id: ['x'; ID_LENGTH].iter().collect(),
        };
        assert!(validate_request_id(&bad_req_id1.into()).is_err());

        // wrong length
        let bad_req_id2 = v1::RequestId {
            request_id: ['a'; ID_LENGTH - 1].iter().collect(),
        };
        assert!(validate_request_id(&bad_req_id2.into()).is_err());

        let good_req_id = v1::RequestId {
            request_id: ['a'; ID_LENGTH].iter().collect(),
        };
        assert!(validate_request_id(&good_req_id.into()).is_err());
    }

    #[test]
    fn test_verify_user_decrypt_eip712() {
        let mut rng = AesRng::from_random_seed();
        let (client_pk, _client_sk) = gen_sig_keys(&mut rng);
        let client_address = alloy_primitives::Address::from_public_key(client_pk.pk());
        let ciphertext = vec![1, 2, 3];
        let (enc_pk, _) = ephemeral_encryption_key_generation::<ml_kem::MlKem512>(&mut rng);
        let key_id = derive_request_id("key_id").unwrap();

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

        let req = kms_grpc::kms::v1::UserDecryptionRequest {
            request_id: Some(v1::RequestId {
                request_id: "dummy request ID".to_owned(),
            }),
            enc_key: bc2wrap::serialize(&enc_pk).unwrap(),
            client_address: client_address.to_checksum(None),
            key_id: Some(key_id.into()),
            typed_ciphertexts: vec![typed_ciphertext],
            domain: Some(domain_msg),
        };

        {
            // happy path
            verify_user_decrypt_eip712(&req).unwrap();
        }
        {
            // use a wrong client address (invalid string length)
            let mut bad_req = req.clone();
            bad_req.client_address = "66f9664f97F2b50F62D13eA064982f936dE76657".to_string();
            match verify_user_decrypt_eip712(&bad_req) {
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
            match verify_user_decrypt_eip712(&bad_req) {
                Ok(_) => panic!("expected failure"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn test_validate_public_decrypt_meta_response() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );

        let request_id = Some(
            derive_request_id("test_validate_public_decrypt_meta_response")
                .unwrap()
                .into(),
        );
        let pivot = PublicDecryptionResponsePayload {
            #[allow(deprecated)] // we have to allow to fill the struct
            digest: vec![],
            verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
            plaintexts: vec![TypedPlaintext {
                bytes: vec![1],
                fhe_type: 1,
            }],
            external_signature: None,
            request_id: request_id.clone(),
        };

        let pivot_buf = bc2wrap::serialize(&pivot).unwrap();

        // use a bad signature (signed with wrong private key)
        {
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &pivot_buf,
                &sk1,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            assert!(
                !validate_public_decrypt_meta_data(&pks, &pivot, &pivot, &signature_buf).unwrap()
            );
        }

        // use a bad signature (malformed signature)
        {
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &pivot_buf,
                &sk0,
            )
            .unwrap();
            // The signature is malformed because it's using bincode to serialize instead of `signature.sig.to_vec()`.
            let signature_buf = bc2wrap::serialize(&signature).unwrap();

            assert!(
                validate_public_decrypt_meta_data(&pks, &pivot, &pivot, &signature_buf).is_err()
            );
        }

        // use a bad signature (signing the wrong value)
        {
            let bad_request_id = Some(
                derive_request_id("bad_test_validate_public_decrypt_meta_response")
                    .unwrap()
                    .into(),
            );
            let bad_value = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: None,
                request_id: bad_request_id,
            };
            let bad_value_buf = bc2wrap::serialize(&bad_value).unwrap();

            let bad_signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &bad_value_buf,
                &sk0,
            )
            .unwrap();
            let bad_signature_buf = bad_signature.sig.to_vec();

            assert!(
                !validate_public_decrypt_meta_data(&pks, &pivot, &pivot, &bad_signature_buf)
                    .unwrap()
            );
        }

        // use a bad response (digest mismatch)
        {
            let bad_request_id = Some(
                derive_request_id("bad_test_validate_public_decrypt_meta_response")
                    .unwrap()
                    .into(),
            );
            let bad_value = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: None,
                request_id: bad_request_id,
            };
            let bad_value_buf = bc2wrap::serialize(&bad_value).unwrap();

            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &bad_value_buf,
                &sk0,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            assert!(
                !validate_public_decrypt_meta_data(&pks, &pivot, &bad_value, &signature_buf)
                    .unwrap()
            );
        }

        // use a bad response (bad validation key)
        {
            let (vk, _sk0) = gen_sig_keys(&mut rng);
            let bad_value = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&vk).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: None,
                request_id: request_id.clone(),
            };
            let bad_value_buf = bc2wrap::serialize(&bad_value).unwrap();

            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &bad_value_buf,
                &sk0,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            assert!(
                !validate_public_decrypt_meta_data(&pks, &pivot, &bad_value, &signature_buf)
                    .unwrap()
            );
        }

        // use a bad response (mismatch plaintext)
        {
            let (vk, _sk0) = gen_sig_keys(&mut rng);
            let bad_value = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&vk).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![0], // normally this is vec![1]
                    fhe_type: 1,
                }],
                external_signature: None,
                request_id,
            };
            let bad_value_buf = bc2wrap::serialize(&bad_value).unwrap();

            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &bad_value_buf,
                &sk0,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            assert!(
                !validate_public_decrypt_meta_data(&pks, &pivot, &bad_value, &signature_buf)
                    .unwrap()
            );
        }

        // happy path
        {
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &pivot_buf,
                &sk0,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec(); // NOTE: signatures are not serialized with bincode

            assert!(
                validate_public_decrypt_meta_data(&pks, &pivot, &pivot, &signature_buf).unwrap()
            );
        }
    }

    #[test]
    fn test_validate_public_decrypt_responses() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );

        let request_id = Some(
            derive_request_id("test_validate_public_decrypt_responses")
                .unwrap()
                .into(),
        );
        let resp0 = {
            let payload = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
                request_id: request_id.clone(),
            };
            let payload_buf = bc2wrap::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &payload_buf,
                &sk0,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            PublicDecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };
        let resp1 = {
            let payload = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
                request_id: request_id.clone(),
            };
            let payload_buf = bc2wrap::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &payload_buf,
                &sk1,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            PublicDecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };

        // in this test we just want to test that we can catch a duplicate validation key
        // the other validation such as signatures are performed in `validate_public_decrypt_meta_data`

        // using an empty payload, we should only get 1 valid response
        {
            let mut empty_resp = resp1.clone();
            empty_resp.payload = None;
            let mut bad_agg_resp = vec![resp0.clone(), empty_resp];
            assert_eq!(
                validate_public_decrypt_responses(&pks, &bad_agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );

            // reverse the aggregate response so the empty one is the first
            bad_agg_resp.reverse();
            assert_eq!(
                validate_public_decrypt_responses(&pks, &bad_agg_resp)
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
                validate_public_decrypt_responses(&pks, &bad_agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );
        }

        // if one of the responses have a wrong number of plaintext, we should only get 1 valid response
        {
            let bad_resp = {
                let payload = PublicDecryptionResponsePayload {
                    verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                    #[allow(deprecated)] // we have to allow to fill the struct
                    digest: vec![],
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
                    request_id,
                };
                let payload_buf = bc2wrap::serialize(&payload).unwrap();
                let signature = &crate::cryptography::signcryption::internal_sign(
                    &DSEP_PUBLIC_DECRYPTION,
                    &payload_buf,
                    &sk1,
                )
                .unwrap();
                let signature_buf = signature.sig.to_vec();

                PublicDecryptionResponse {
                    signature: signature_buf,
                    payload: Some(payload),
                }
            };
            let agg_resp = vec![resp0.clone(), bad_resp];
            assert_eq!(
                validate_public_decrypt_responses(&pks, &agg_resp)
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
                validate_public_decrypt_responses(&pks, &agg_resp)
                    .unwrap()
                    .unwrap()
                    .len(),
                2
            );
        }
    }

    #[test]
    fn test_validate_public_decrypt_responses_against_request() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );

        let request_id = Some(derive_request_id("PublicDecryptionRequest").unwrap().into());
        let request = PublicDecryptionRequest {
            request_id: request_id.clone(),
            ciphertexts: vec![TypedCiphertext {
                ciphertext: vec![1, 2, 3, 4],
                fhe_type: 1,
                external_handle: vec![1, 2, 3, 4],
                ciphertext_format: 1,
            }],
            key_id: Some(
                derive_request_id("PublicDecryptionRequest key_id")
                    .unwrap()
                    .into(),
            ),
            domain: None,
        };

        let resp0 = {
            let payload = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
                request_id: request_id.clone(),
            };
            let payload_buf = bc2wrap::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &payload_buf,
                &sk0,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            PublicDecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };
        let resp1 = {
            let payload = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: 1,
                }],
                external_signature: Some(vec![]),
                request_id: request_id.clone(),
            };
            let payload_buf = bc2wrap::serialize(&payload).unwrap();
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_PUBLIC_DECRYPTION,
                &payload_buf,
                &sk1,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();

            PublicDecryptionResponse {
                signature: signature_buf,
                payload: Some(payload),
            }
        };

        // invalid aggregate response, e.g., when there are none
        {
            let agg_resp = vec![];
            assert!(validate_public_decrypt_responses_against_request(
                &pks,
                Some(request.clone()),
                &agg_resp,
                1
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_INVALID_AGG_RESP));
        }

        // not enough decryption responses
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert!(validate_public_decrypt_responses_against_request(
                &pks,
                Some(request.clone()),
                &agg_resp,
                3
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_NOT_ENOUGH_RESP));
        }

        // ciphertext count is wrong
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let bad_request = PublicDecryptionRequest {
                request_id: Some(derive_request_id("PublicDecryptionRequest").unwrap().into()),
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
                key_id: Some(
                    derive_request_id("PublicDecryptionRequest key_id")
                        .unwrap()
                        .into(),
                ),
                domain: None,
            };
            assert!(validate_public_decrypt_responses_against_request(
                &pks,
                Some(bad_request),
                &agg_resp,
                2
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_CT_COUNT));
        }

        // plaintext type is wrong
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let bad_request = PublicDecryptionRequest {
                request_id: Some(derive_request_id("PublicDecryptionRequest").unwrap().into()),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: vec![1, 2, 3, 4],
                    fhe_type: 2, // we change the fhe_type so it's the wrong request
                    external_handle: vec![1, 2, 3, 4],
                    ciphertext_format: 1,
                }],
                key_id: Some(
                    derive_request_id("PublicDecryptionRequest key_id")
                        .unwrap()
                        .into(),
                ),
                domain: None,
            };
            assert!(validate_public_decrypt_responses_against_request(
                &pks,
                Some(bad_request),
                &agg_resp,
                2
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE));
        }

        // request ID
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let bad_request = PublicDecryptionRequest {
                // wrong request ID
                request_id: Some(
                    derive_request_id("bad PublicDecryptionRequest")
                        .unwrap()
                        .into(),
                ),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: vec![1, 2, 3, 4],
                    fhe_type: 1,
                    external_handle: vec![1, 2, 3, 4],
                    ciphertext_format: 1,
                }],
                key_id: Some(
                    derive_request_id("PublicDecryptionRequest key_id")
                        .unwrap()
                        .into(),
                ),
                domain: None,
            };
            assert!(validate_public_decrypt_responses_against_request(
                &pks,
                Some(bad_request),
                &agg_resp,
                2
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK));
        }

        // request is empty, which should pass
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            validate_public_decrypt_responses_against_request(&pks, None, &agg_resp, 2).unwrap();
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            validate_public_decrypt_responses_against_request(
                &pks,
                Some(request.clone()),
                &agg_resp,
                2,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_select_most_common_dec() {
        let request_id = Some(
            derive_request_id("test_select_most_common_dec")
                .unwrap()
                .into(),
        );
        let plaintexts = vec![TypedPlaintext {
            bytes: vec![1],
            fhe_type: 1,
        }];
        let resp0 = {
            let payload = PublicDecryptionResponsePayload {
                verification_key: vec![],
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: plaintexts.clone(),
                external_signature: Some(vec![]),
                request_id: request_id.clone(),
            };
            PublicDecryptionResponse {
                signature: vec![],
                payload: Some(payload),
            }
        };

        // two responses, second response has modified digest
        {
            let mut resp1 = resp0.clone();
            resp1.payload.iter_mut().for_each(|x| {
                x.request_id = Some(
                    derive_request_id("bad_select_most_common_dec")
                        .unwrap()
                        .into(),
                )
            });
            let agg_resp = vec![resp0.clone(), resp1];
            assert_eq!(select_most_common_public_dec(2, &agg_resp), None);
        }

        // two responses, second response has modified plaintext
        {
            let mut resp1 = resp0.clone();
            resp1.payload.iter_mut().for_each(|x| {
                x.plaintexts = vec![TypedPlaintext {
                    bytes: vec![0],
                    fhe_type: 1,
                }]
            });
            let agg_resp = vec![resp0.clone(), resp1];
            assert_eq!(select_most_common_public_dec(2, &agg_resp), None);
        }

        // happy path
        {
            let resp1 = resp0.clone();
            let agg_resp = vec![resp0.clone(), resp1];
            assert_eq!(
                select_most_common_public_dec(2, &agg_resp),
                resp0.payload.clone()
            );
        }

        let resp1 = resp0.clone();
        let resp2 = {
            let bad_request_id = Some(
                derive_request_id("bad_select_most_common_dec")
                    .unwrap()
                    .into(),
            );
            let payload = PublicDecryptionResponsePayload {
                verification_key: vec![],
                #[allow(deprecated)] // we have to allow to fill the struct
                digest: vec![],
                plaintexts: plaintexts.clone(),
                external_signature: Some(vec![]),
                request_id: bad_request_id,
            };
            PublicDecryptionResponse {
                signature: vec![],
                payload: Some(payload),
            }
        };

        // threshold is too high
        {
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];
            assert_eq!(select_most_common_public_dec(3, &agg_resp), None);
        }

        // second response has a modified field unrelated to the hashmap key
        {
            let mut resp1 = resp1.clone();
            resp1.signature = vec![2, 2, 2, 2];
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];
            assert_eq!(
                select_most_common_public_dec(2, &agg_resp),
                resp1.payload.clone()
            );
        }
    }
}
