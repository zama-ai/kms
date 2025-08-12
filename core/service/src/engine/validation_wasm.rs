use std::collections::{HashMap, HashSet};

use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::Address;
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{TypedSigncryptedCiphertext, UserDecryptionResponse, UserDecryptionResponsePayload},
    rpc_types::FheTypeResponse,
};
use threshold_fhe::hashing::DomainSep;

use crate::{
    anyhow_error_and_log,
    client::{compute_link, ParsedUserDecryptionRequest},
    cryptography::{
        internal_crypto_types::{PublicEncKey, PublicSigKey, Signature, UnifiedPublicEncKey},
        signcryption::internal_verify_sig,
    },
    some_or_err,
};

pub(crate) const DSEP_USER_DECRYPTION: DomainSep = *b"USER_DEC";

const ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGH: &str =
    "Expected external signature of length 65 Bytes";
const ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE: &str =
    "External PT signature verification failed";

const ERR_VALIDATE_USER_DECRYPTION_BAD_FHETYPE_LENGTH: &str =
    "Incorrect FHE type lengths in user decryption response";
const ERR_VALIDATE_USER_DECRYPTION_FHETYPE_MISMATCH: &str =
    "FHE type in user decryption response mismatch";
const ERR_VALIDATE_USER_DECRYPTION_DIGEST_MISMATCH: &str =
    "Digest in user decryption response mismatch";
const ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE: &str =
    "Missing signature in user decryption response";
const ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND: &str = "ID claimed in payload not found";
const ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS: &str =
    "ID or address claimed in payload is incorrect";

/// check that the external signature on the decryption result(s) is valid, i.e. was made by one of the supplied addresses
pub(crate) fn check_ext_user_decryption_signature(
    external_sig: &[u8],
    payload: &UserDecryptionResponsePayload,
    request: &ParsedUserDecryptionRequest,
    eip712_domain: &Eip712Domain,
    expected_addr: &alloy_primitives::Address,
) -> anyhow::Result<()> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow::anyhow!(
            "{}, but got {:?}",
            ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGH,
            external_sig.len()
        ));
    }

    // this reverses the call to `signature.as_bytes()` that we use for serialization
    let sig =
        alloy_signer::Signature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0);

    // NOTE: we need to support legacy user_pk, so try to deserialize MlKem1024 first
    let unified_pk =
        match bc2wrap::deserialize::<PublicEncKey<ml_kem::MlKem1024>>(request.enc_key()) {
            Ok(pk) => UnifiedPublicEncKey::MlKem1024(pk),
            Err(_) => tfhe::safe_serialization::safe_deserialize::<UnifiedPublicEncKey>(
                request.enc_key(),
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .map_err(|e| anyhow::anyhow!("Error deserializing UnifiedPublicEncKey: {e}"))?,
        };
    let hash =
        crate::compute_user_decrypt_message_hash(payload, eip712_domain, &unified_pk, vec![])?;

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::info!("recovered address: {}", addr);

    if addr != *expected_addr {
        anyhow::bail!(ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE);
    }

    Ok(())
}

fn validate_user_decrypt_meta_data_and_signature(
    server_addreses: &HashMap<u32, Address>,
    client_request: &ParsedUserDecryptionRequest,
    pivot_resp: &UserDecryptionResponsePayload,
    other_resp: &UserDecryptionResponsePayload,
    signature: &[u8],
    external_signature: &[u8],
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<()> {
    let pivot_type = pivot_resp.fhe_types()?;
    let check_type = other_resp.fhe_types()?;
    if pivot_type.len() != check_type.len() || pivot_type.is_empty() || check_type.is_empty() {
        anyhow::bail!(
            "{}: {}, {}",
            ERR_VALIDATE_USER_DECRYPTION_BAD_FHETYPE_LENGTH,
            pivot_type.len(),
            check_type.len()
        );
    }

    for i in 0..pivot_type.len() {
        if pivot_type[i] != check_type[i] {
            anyhow::bail!(
                "{}: pivot is has verification key {:?} with type {:?}, other has verification key {:?} with type {:?}",
                ERR_VALIDATE_USER_DECRYPTION_FHETYPE_MISMATCH,
                &pivot_resp.verification_key,
                pivot_type[i],
                &other_resp.verification_key,
                check_type[i],
            );
        }
    }

    if pivot_resp.digest != other_resp.digest {
        anyhow::bail!(
                    "{}: pivot has verification key {:?} gave digest {:?}, other has verification key {:?} with digest {:?}",
                ERR_VALIDATE_USER_DECRYPTION_DIGEST_MISMATCH,
                    pivot_resp.verification_key,
                    pivot_resp.digest,
                    other_resp.verification_key,
                    other_resp.digest,
                );
    }

    let resp_verf_key: PublicSigKey = bc2wrap::deserialize(&other_resp.verification_key)?;
    let resp_addr = alloy_signer::utils::public_key_to_address(resp_verf_key.pk());

    let expected_addr = if let Some(expected_addr) = server_addreses.get(&other_resp.party_id) {
        if *expected_addr != resp_addr {
            anyhow::bail!(ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS)
        }
        expected_addr
    } else {
        anyhow::bail!(ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND)
    };

    // Prefer ECDSA signature over the eip712 one
    if signature.is_empty() {
        // check signature
        if external_signature.is_empty() {
            return Err(anyhow_error_and_log(
                ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE,
            ));
        }

        check_ext_user_decryption_signature(
            external_signature,
            other_resp,
            client_request,
            eip712_domain,
            expected_addr,
        )
        .inspect_err(|e| tracing::warn!("signature on received response is not valid ({})!", e))?;
    } else {
        let sig = Signature {
            sig: k256::ecdsa::Signature::from_slice(signature)?,
        };
        // NOTE that we cannot use `BaseKmsStruct::verify_sig`
        // because `BaseKmsStruct` cannot be compiled for wasm (it has an async mutex).
        if internal_verify_sig(
            &DSEP_USER_DECRYPTION,
            &bc2wrap::serialize(&other_resp)?,
            &sig,
            &resp_verf_key,
        )
        .is_err()
        {
            anyhow::bail!("Signature on received response is not valid!");
        }
    }

    Ok(())
}

#[derive(Hash, PartialEq, Eq)]
struct TypedSigncryptedCiphertextInvariants {
    packing_factor: u32,
    fhe_type: i32,
    external_handle: Vec<u8>,
}

impl From<TypedSigncryptedCiphertext> for TypedSigncryptedCiphertextInvariants {
    fn from(value: TypedSigncryptedCiphertext) -> Self {
        Self {
            packing_factor: value.packing_factor,
            fhe_type: value.fhe_type,
            external_handle: value.external_handle,
        }
    }
}

/// Fields in [UserDecryptionResponsePayload] that should remain the same
/// for the same request.
#[derive(Hash, PartialEq, Eq)]
struct UserDecryptionResponseInvariants {
    degree: u32,
    digest: Vec<u8>,
    signcrypted_ciphertext_metadata: Vec<TypedSigncryptedCiphertextInvariants>,
}

impl TryFrom<UserDecryptionResponsePayload> for UserDecryptionResponseInvariants {
    type Error = anyhow::Error;
    fn try_from(value: UserDecryptionResponsePayload) -> anyhow::Result<Self> {
        Ok(Self {
            degree: value.degree,
            digest: value.digest,
            signcrypted_ciphertext_metadata: value
                .signcrypted_ciphertexts
                .into_iter()
                .map(|x| x.into())
                .collect(),
        })
    }
}

pub(crate) fn select_most_common<'a, P, T>(
    min_occurence: usize,
    agg_resp: impl Iterator<Item = Option<&'a P>>,
) -> anyhow::Result<Option<usize>>
where
    P: Clone + 'a,
    T: TryFrom<P, Error = anyhow::Error> + std::cmp::Eq + std::hash::Hash,
{
    // this hashmap is keyed on [T]
    // and its values contain a tuple (x, y), where x is the occurence and y is the original index
    let mut occurence_map: HashMap<T, (usize, usize), _> = HashMap::new();
    for (i, resp) in agg_resp.enumerate() {
        match resp {
            Some(inner) => {
                occurence_map
                    .entry(inner.clone().try_into()?)
                    .or_insert_with(|| (0, i))
                    .0 += 1;
            }
            None => {
                continue;
            }
        }
    }

    // turn the values in the hashmap to a vector and sort by occurence
    let first = occurence_map
        .values()
        .sorted_by(|a, b| a.0.cmp(&b.0))
        .next_back();

    Ok(match first {
        Some(inner) => {
            if inner.0 >= min_occurence {
                Some(inner.1)
            } else {
                None
            }
        }
        None => None,
    })
}

fn select_most_common_user_dec(
    min_occurence: usize,
    agg_resp: &[UserDecryptionResponse],
) -> Option<UserDecryptionResponsePayload> {
    let iter = agg_resp.iter().map(|resp| resp.payload.as_ref());
    let idx = match select_most_common::<_, UserDecryptionResponseInvariants>(min_occurence, iter) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!("Error selecting most common user decryption response: {e}");
            None
        }
    };
    idx.and_then(|i| agg_resp[i].payload.clone())
}

fn validate_user_decrypt_responses(
    server_addresses: &HashMap<u32, Address>,
    client_request: &ParsedUserDecryptionRequest,
    eip712_domain: &Eip712Domain,
    agg_resp: &[UserDecryptionResponse],
) -> anyhow::Result<Option<Vec<UserDecryptionResponsePayload>>> {
    if agg_resp.is_empty() {
        tracing::warn!("There are no responses");
        return Ok(None);
    }

    // Pick a pivot response
    let threshold = (server_addresses.len() - 1) / 3; // Note that this is floored division.
    let min_occurence = threshold + 1; // We need t+1 responses at least to find the pivot response.
    let pivot_payload = match select_most_common_user_dec(min_occurence, agg_resp) {
        Some(inner) => inner,
        None => anyhow::bail!("Cannot find user decryption pivot"),
    };
    let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.len());
    let mut party_ids = HashSet::new();
    let mut verification_keys = HashSet::new();

    // if the pivot response degree does not match the threshold, we cannot proceed
    if pivot_payload.degree != threshold as u32 {
        anyhow::bail!(
                "Pivot user decrypt responses gave degree {} which does not match expected threshold {} for {} known servers",
                pivot_payload.degree,
                threshold,
                server_addresses.len()
            );
    }

    for cur_resp in agg_resp {
        let cur_payload = match &cur_resp.payload {
            Some(cur_payload) => cur_payload,
            None => {
                tracing::warn!("No payload in current response from server!");
                continue;
            }
        };

        // Validate that all the responses agree with the pivot on the static parts of the
        // response
        if let Err(e) = validate_user_decrypt_meta_data_and_signature(
            server_addresses,
            client_request,
            &pivot_payload,
            cur_payload,
            &cur_resp.signature,
            &cur_resp.external_signature,
            eip712_domain,
        ) {
            tracing::warn!(
                "User decryption validation failed for party {} with error: {e:?}",
                cur_payload.party_id
            );
            continue;
        }
        if pivot_payload.degree != cur_payload.degree {
            tracing::warn!(
                    "Server with claimed ID {} gave degree {} which is inconsistent with the pivot response {}",
                    cur_payload.party_id, cur_payload.degree, pivot_payload.degree
                );
            continue;
        }
        // Sanity check the ID of the server.
        // However, this will not catch all cheating since a server could claim the ID of another server
        // and we can't know who lies without consulting the verification key to ID mapping on the blockchain.
        // Furthermore, observe that we assume the optimal threshold is set.
        if cur_payload.party_id > cur_payload.degree * 3 + 1 {
            tracing::warn!(
                "Server claimed ID {} is too large. The largest allowed id {}",
                cur_payload.party_id,
                cur_payload.degree * 3 + 1
            );
            continue;
        }
        if cur_payload.party_id == 0 {
            tracing::warn!("A server ID is set to 0");
            continue;
        }
        if party_ids.contains(&cur_payload.party_id) {
            tracing::warn!(
                "At least two servers gave the same ID {}",
                cur_payload.party_id,
            );
            continue;
        }

        // Check that verification keys are unique
        party_ids.insert(cur_payload.party_id);
        if verification_keys.contains(&cur_payload.verification_key) {
            tracing::warn!(
                "At least two servers gave the same verification key {}",
                hex::encode(&cur_payload.verification_key),
            );
            continue;
        }

        if pivot_payload.signcrypted_ciphertexts.len() != cur_payload.signcrypted_ciphertexts.len()
        {
            tracing::warn!(
                "Server who gave ID {} has different number of ciphertexts than the pivot response {} ",
                cur_payload.party_id, pivot_payload.party_id
            );
            continue;
        }
        // Check that the packing factor is consistent across all ciphertexts
        // Observe that we have already validated the amount of ciphertexts is equal in both the pivot and current payloads.
        // Hence we can use `zip_eq` to compare the packing factors.
        if !pivot_payload
            .signcrypted_ciphertexts
            .iter()
            .map(|ct| ct.packing_factor)
            .zip_eq(
                cur_payload
                    .signcrypted_ciphertexts
                    .iter()
                    .map(|ct| ct.packing_factor),
            )
            .all(|(left, right)| left == right)
        {
            tracing::warn!("Inconsistent packing factor for {}", cur_payload.party_id);
            continue;
        }

        // only add the verified keys and responses at the end
        verification_keys.insert(cur_payload.verification_key.clone());
        resp_parsed_payloads.push(cur_payload.clone());
    }

    if resp_parsed_payloads.len() <= pivot_payload.degree as usize {
        tracing::warn!("Not enough correct responses to user-decrypt the data!");
        Ok(None)
    } else {
        Ok(Some(resp_parsed_payloads))
    }
}

/// Validates the aggregated user decryption responses received from the servers
/// against the given user decryption request. Returns the validated responses
/// mapped to the server ID on success.
pub(crate) fn validate_user_decrypt_responses_against_request(
    server_addresses: &HashMap<u32, Address>,
    client_request: &ParsedUserDecryptionRequest,
    eip712_domain: &Eip712Domain,
    agg_resp: &[UserDecryptionResponse],
) -> anyhow::Result<Option<Vec<UserDecryptionResponsePayload>>> {
    let resp_parsed = some_or_err(
        validate_user_decrypt_responses(server_addresses, client_request, eip712_domain, agg_resp)?,
        "Could not validate the aggregated responses".to_string(),
    )?;
    let expected_link = compute_link(client_request, eip712_domain)?;
    let pivot_resp = resp_parsed[0].clone();
    if expected_link != pivot_resp.digest {
        tracing::warn!("The user decryption response is not linked to the correct request");
        return Ok(None);
    }

    Ok(Some(resp_parsed))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{
        TypedSigncryptedCiphertext, UserDecryptionResponse, UserDecryptionResponsePayload,
    };
    use rand::SeedableRng;

    use crate::{
        client::{compute_link, CiphertextHandle, ParsedUserDecryptionRequest},
        cryptography::{
            internal_crypto_types::{gen_sig_keys, PublicSigKey, UnifiedPublicEncKey},
            signcryption::ephemeral_encryption_key_generation,
        },
        dummy_domain,
        engine::{
            base::compute_external_user_decrypt_signature,
            validation_wasm::{
                ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE,
                ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND,
                ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS,
            },
        },
    };

    use super::{
        check_ext_user_decryption_signature, select_most_common_user_dec,
        validate_user_decrypt_meta_data_and_signature, validate_user_decrypt_responses,
        validate_user_decrypt_responses_against_request, DSEP_USER_DECRYPTION,
        ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGH, ERR_VALIDATE_USER_DECRYPTION_BAD_FHETYPE_LENGTH,
        ERR_VALIDATE_USER_DECRYPTION_DIGEST_MISMATCH,
        ERR_VALIDATE_USER_DECRYPTION_FHETYPE_MISMATCH,
        ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE,
    };

    #[test]
    fn test_check_ext_user_decryption_signature() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, _sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let kms_addrs = pks
            .iter()
            .map(|(i, pk)| (*i, alloy_primitives::Address::from_public_key(pk.pk())))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let (eph_client_pk, _eph_client_sk) =
            ephemeral_encryption_key_generation::<ml_kem::MlKem512>(&mut rng);
        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let ciphertext_handle = vec![5, 6, 7, 8];

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &UnifiedPublicEncKey::MlKem512(eph_client_pk.clone()),
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        let domain = dummy_domain();
        let request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed
            alloy_primitives::Address::from_public_key(client_vk.pk()),
            enc_key_buf,
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            domain.verifying_contract.unwrap(),
        );

        let payload = UserDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
            digest: vec![1, 2, 3, 4],
            signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                fhe_type: 1,
                signcrypted_ciphertext: vec![1, 2, 3, 4],
                external_handle: ciphertext_handle.clone(),
                packing_factor: 1,
            }],
            party_id: 1,
            degree: 1,
        };
        let external_sig = compute_external_user_decrypt_signature(
            &sk0,
            &payload,
            &domain,
            &eph_client_pk.to_unified(),
            vec![],
        )
        .unwrap();

        // incorrect external signature length
        {
            assert!(check_ext_user_decryption_signature(
                &external_sig[0..64],
                &payload,
                &request,
                &domain,
                &kms_addrs[&1],
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGH));
        }

        // bad signature due to bad signing key
        {
            let (_vk_bad, sk_bad) = gen_sig_keys(&mut rng);
            let bad_external_sig = compute_external_user_decrypt_signature(
                &sk_bad,
                &payload,
                &domain,
                &eph_client_pk.to_unified(),
                vec![],
            )
            .unwrap();
            assert!(check_ext_user_decryption_signature(
                &bad_external_sig,
                &payload,
                &request,
                &domain,
                &kms_addrs[&1],
            )
            .is_err());
        }

        // bad signature due to bad domain
        {
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Authorization token",
                version: "1",
                chain_id: 1234, // incorrect chain ID
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            assert!(check_ext_user_decryption_signature(
                &external_sig,
                &payload,
                &request,
                &bad_domain,
                &kms_addrs[&1],
            )
            .is_err());
        }

        // check that we detect the error if payload is modified
        {
            let mut bad_payload = payload.clone();
            bad_payload.party_id = 2; // modify ID
            assert!(check_ext_user_decryption_signature(
                &external_sig,
                &bad_payload,
                &request,
                &domain,
                &kms_addrs[&1],
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE));
        }

        // happy path
        {
            check_ext_user_decryption_signature(
                &external_sig,
                &payload,
                &request,
                &domain,
                &kms_addrs[&1],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_validate_user_decrypt_meta_data_and_signature() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, _sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let server_addresses = pks
            .iter()
            .map(|(i, pk)| (*i, alloy_primitives::Address::from_public_key(pk.pk())))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let (eph_client_pk, _eph_client_sk) =
            ephemeral_encryption_key_generation::<ml_kem::MlKem512>(&mut rng);

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &UnifiedPublicEncKey::MlKem512(eph_client_pk.clone()),
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let dummy_domain = dummy_domain();
        let ciphertext_handle = vec![5, 6, 7, 8];

        let client_request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed here because we're testing response validation
            alloy_primitives::Address::from_public_key(client_vk.pk()),
            enc_key_buf,
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            dummy_domain.verifying_contract.unwrap(),
        );

        let pivot_resp = UserDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
            digest: vec![1, 2, 3, 4],
            signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                fhe_type: 1,
                signcrypted_ciphertext: vec![1, 2, 3, 4],
                external_handle: ciphertext_handle.clone(),
                packing_factor: 1,
            }],
            party_id: 1,
            degree: 1,
        };
        let external_signature = compute_external_user_decrypt_signature(
            &sk0,
            &pivot_resp,
            &dummy_domain,
            &eph_client_pk.to_unified(),
            vec![],
        )
        .unwrap();

        // incorrect length
        {
            let other_resp = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                digest: vec![1, 2, 3, 4],
                signcrypted_ciphertexts: vec![], // the ciphertext is just an empty vector
                party_id: 1,
                degree: 1,
            };
            assert!(validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &other_resp,
                &[], // the ECDSA signature may be empty, thus we check the external one
                &external_signature,
                &dummy_domain,
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_USER_DECRYPTION_BAD_FHETYPE_LENGTH));
        }

        // mismatch type
        {
            let other_resp = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                digest: vec![1, 2, 3, 4],
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 2, // in the pivot the type is 1
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 1,
            };
            assert!(validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &other_resp,
                &[], // the ECDSA signature may be empty, thus we check the external one
                &external_signature,
                &dummy_domain,
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_USER_DECRYPTION_FHETYPE_MISMATCH));
        }

        // digest mismatch
        {
            let other_resp = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                digest: vec![1, 2, 3, 4, 5], // the digest should be [1, 2, 3, 4]
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 1,
            };
            assert!(validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &other_resp,
                &[], // the ECDSA signature may be empty, thus we check the external one
                &external_signature,
                &dummy_domain,
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_USER_DECRYPTION_DIGEST_MISMATCH));
        }

        // no signatures are provided
        {
            assert!(validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &pivot_resp,
                &[], // the ECDSA signature may be empty, thus we check the external one
                &[],
                &dummy_domain,
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE));
        }

        // if the ID is changed to something that does not exist, return error
        {
            let mut other_resp = pivot_resp.clone();
            other_resp.party_id = 10;
            assert!(validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &other_resp,
                &[],
                &external_signature,
                &dummy_domain,
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND));
        }

        // if the ID does not match with the claimed address, return error
        {
            let mut other_resp = pivot_resp.clone();
            other_resp.party_id = 2; // originally the ID is 1
            assert!(validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &other_resp,
                &[],
                &external_signature,
                &dummy_domain,
            )
            .unwrap_err()
            .to_string()
            .contains(ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS));
        }

        // no need to explicitly test the signature issues again since they were tested in [test_check_ext_user_decryption_signature]

        // happy path for empty ECDSA, so we check external signature
        {
            validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &pivot_resp,
                &[], // the ECDSA signature may be empty, thus we check the external one
                &external_signature,
                &dummy_domain,
            )
            .unwrap();
        }

        // happy path for empty external_signature, so we check ECDSA
        {
            let pivot_buf = bc2wrap::serialize(&pivot_resp).unwrap();
            let signature = &crate::cryptography::signcryption::internal_sign(
                &DSEP_USER_DECRYPTION,
                &pivot_buf,
                &sk0,
            )
            .unwrap();
            let signature_buf = signature.sig.to_vec();
            validate_user_decrypt_meta_data_and_signature(
                &server_addresses,
                &client_request,
                &pivot_resp,
                &pivot_resp,
                &signature_buf,
                &[],
                &dummy_domain,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_validate_user_decrypt_responses() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, sk2) = gen_sig_keys(&mut rng);
        let (vk3, sk3) = gen_sig_keys(&mut rng);
        let (vk4, sk4) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk1, vk2, vk3, vk4]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let server_addresses = pks
            .iter()
            .map(|(i, pk)| (*i, alloy_primitives::Address::from_public_key(pk.pk())))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let (eph_client_pk, _eph_client_sk) =
            ephemeral_encryption_key_generation::<ml_kem::MlKem512>(&mut rng);
        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let dummy_domain = dummy_domain();
        let ciphertext_handle = vec![5, 6, 7, 8];

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &UnifiedPublicEncKey::MlKem512(eph_client_pk.clone()),
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let client_request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed here because we're testing response validation
            alloy_primitives::Address::from_public_key(client_vk.pk()),
            enc_key_buf,
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            dummy_domain.verifying_contract.unwrap(),
        );

        let resp1 = {
            let payload0 = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                digest: vec![1, 2, 3, 4],
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk1,
                &payload0,
                &dummy_domain,
                &eph_client_pk.to_unified(),
                vec![],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                external_signature,
                payload: Some(payload0),
                extra_data: vec![],
            }
        };

        let resp2 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                digest: vec![1, 2, 3, 4],
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 2,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk2,
                &payload,
                &dummy_domain,
                &eph_client_pk.to_unified(),
                vec![],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                external_signature,
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        let resp3 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&3]).unwrap(),
                digest: vec![1, 2, 3, 4],
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 3,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk3,
                &payload,
                &dummy_domain,
                &eph_client_pk.to_unified(),
                vec![],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                external_signature,
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        let resp4 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&4]).unwrap(),
                digest: vec![1, 2, 3, 4],
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 4,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk4,
                &payload,
                &dummy_domain,
                &eph_client_pk.to_unified(),
                vec![],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                external_signature,
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        // happy path / sunshine; we should have 4 valid responses
        {
            let agg_resp = vec![resp1.clone(), resp2.clone(), resp3.clone(), resp4.clone()];

            assert_eq!(
                validate_user_decrypt_responses(
                    &server_addresses,
                    &client_request,
                    &dummy_domain,
                    &agg_resp
                )
                .unwrap()
                .unwrap()
                .len(),
                4
            );
        }

        // empty responses, should return None
        {
            assert!(validate_user_decrypt_responses(
                &server_addresses,
                &client_request,
                &dummy_domain,
                &[],
            )
            .unwrap()
            .is_none());
        }

        // empty payload
        {
            // we need at least 2 valid responses because our degree is 1,
            // otherwise None will be returned since there are not enough responses
            let mut bad_resp2 = resp3.clone();
            bad_resp2.payload = None;
            let agg_resp = vec![resp1.clone(), resp2.clone(), bad_resp2];

            // We will have 2 accepted responses because
            // the third one does not have a payload
            assert_eq!(
                validate_user_decrypt_responses(
                    &server_addresses,
                    &client_request,
                    &dummy_domain,
                    &agg_resp
                )
                .unwrap()
                .unwrap()
                .len(),
                2
            );
        }

        // not enough correct payloads (only 1 is valid)
        // 2 "good enough ones" are needed to find a pivot for t=1
        {
            let mut bad_resp2 = resp2.clone();
            bad_resp2.payload = None; // no payload here, cannot be used for pivot
            let mut bad_resp3 = resp3.clone();
            bad_resp3.payload.as_mut().unwrap().party_id = 2; // payload, but with wrong party ID (i.e. not matching its key) here, otherwise good as pivot

            let agg_resp = vec![resp1.clone(), bad_resp2, bad_resp3];

            assert!(validate_user_decrypt_responses(
                &server_addresses,
                &client_request,
                &dummy_domain,
                &agg_resp
            )
            .unwrap()
            .is_none());
        }

        // one repsonse has a wrong degree, but should pass since majority is fine
        {
            let mut bad_resp2 = resp2.clone();
            bad_resp2.payload.as_mut().unwrap().degree = 35; // wrong degree here
            let agg_resp = vec![resp1.clone(), bad_resp2, resp3.clone()];

            assert_eq!(
                validate_user_decrypt_responses(
                    &server_addresses,
                    &client_request,
                    &dummy_domain,
                    &agg_resp
                )
                .unwrap()
                .unwrap()
                .len(),
                2
            );
        }

        // degree (0) does not match threshold (1) for 4 parties, so we must get an error
        {
            let mut bad_resp3 = resp3.clone();
            bad_resp3.payload.as_mut().unwrap().degree = 0; // payload, but with degree
            let mut bad_resp2 = resp2.clone();
            bad_resp2.payload.as_mut().unwrap().degree = 0; // payload, but with degree

            let agg_resp = vec![bad_resp2, bad_resp3];

            assert!(validate_user_decrypt_responses(
                &server_addresses,
                &client_request,
                &dummy_domain,
                &agg_resp
            )
            .unwrap_err().to_string()
            .contains("Pivot user decrypt responses gave degree 0 which does not match expected threshold 1 for 4 known servers"));
        }

        let run_with_customized_resp2 = |party_id, digest, pk, packing_factor| {
            // the correct parameters should be party_id = 3, digest = vec![1,2,3,4], pk = &pks[2], packing_factor = 1
            let bad_resp2 = {
                let payload = UserDecryptionResponsePayload {
                    verification_key: bc2wrap::serialize(pk).unwrap(),
                    digest,
                    signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                        fhe_type: 1,
                        signcrypted_ciphertext: vec![1, 2, 3, 4],
                        external_handle: ciphertext_handle.clone(),
                        packing_factor,
                    }],
                    party_id, // invalid party ID
                    degree: 1,
                };
                let external_signature = compute_external_user_decrypt_signature(
                    &sk3,
                    &payload,
                    &dummy_domain,
                    &eph_client_pk.to_unified(),
                    vec![],
                )
                .unwrap();
                UserDecryptionResponse {
                    signature: vec![],
                    external_signature,
                    payload: Some(payload),
                    extra_data: vec![],
                }
            };
            let agg_resp = vec![resp1.clone(), resp2.clone(), bad_resp2];

            assert_eq!(
                validate_user_decrypt_responses(
                    &server_addresses,
                    &client_request,
                    &dummy_domain,
                    &agg_resp
                )
                .unwrap()
                .unwrap()
                .len(),
                2
            );
        };

        // sanity check the closure passes with the correct arguments
        {
            let result = std::panic::catch_unwind(|| {
                run_with_customized_resp2(3, vec![1, 2, 3, 4], &pks[&3], 1);
            });
            assert!(result.is_err());
        }

        // digest mismatch
        {
            run_with_customized_resp2(3, vec![1, 2, 3, 4, 5], &pks[&3], 1);
        }

        // invalid party ID (too big)
        {
            run_with_customized_resp2(10, vec![1, 2, 3, 4], &pks[&3], 1);
        }

        // invalid party ID (cannot be 0)
        {
            run_with_customized_resp2(0, vec![1, 2, 3, 4], &pks[&3], 1);
        }

        // invalid party ID (same as another party)
        {
            run_with_customized_resp2(1, vec![1, 2, 3, 4], &pks[&3], 1);
        }

        // invalid packing factor
        {
            run_with_customized_resp2(3, vec![1, 2, 3, 4], &pks[&3], 2);
        }

        // invalid verification key
        {
            let (vk, _sk) = gen_sig_keys(&mut rng);
            run_with_customized_resp2(3, vec![1, 2, 3, 4], &vk, 1);
        }

        // happy path
        {
            let agg_resp = vec![resp1.clone(), resp2.clone(), resp3.clone()];
            assert_eq!(
                validate_user_decrypt_responses(
                    &server_addresses,
                    &client_request,
                    &dummy_domain,
                    &agg_resp
                )
                .unwrap()
                .unwrap()
                .len(),
                3
            );
        }
    }

    #[test]
    fn test_validate_user_decrypt_responses_against_request() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, sk2) = gen_sig_keys(&mut rng);
        let (vk3, _sk3) = gen_sig_keys(&mut rng);
        let (vk4, _sk4) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk1, vk2, vk3, vk4]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let server_addresses = pks
            .iter()
            .map(|(i, pk)| (*i, alloy_primitives::Address::from_public_key(pk.pk())))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let (eph_client_pk, _eph_client_sk) =
            ephemeral_encryption_key_generation::<ml_kem::MlKem512>(&mut rng);
        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let dummy_domain = dummy_domain();
        let ciphertext_handle = vec![5, 6, 7, 8];

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &UnifiedPublicEncKey::MlKem512(eph_client_pk.clone()),
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let client_request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed here because we're testing response validation
            alloy_primitives::Address::from_public_key(client_vk.pk()),
            enc_key_buf.clone(),
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            dummy_domain.verifying_contract.unwrap(),
        );

        let digest = compute_link(&client_request, &dummy_domain).unwrap();

        let resp0 = {
            let payload0 = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk1,
                &payload0,
                &dummy_domain,
                &eph_client_pk.to_unified(),
                vec![],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                external_signature,
                payload: Some(payload0),
                extra_data: vec![],
            }
        };

        let resp1 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 2,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk2,
                &payload,
                &dummy_domain,
                &eph_client_pk.to_unified(),
                vec![],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                external_signature,
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        // wrong link
        // Note that we cannot change the domain or other parts of the response to cause the failure
        // because that would lead to other failures in [validate_user_decrypt_responses], which are already tested.
        // So we change the client request to cause the failure.
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];

            let (bad_client_vk, _bad_client_sk) = gen_sig_keys(&mut rng);
            let bad_client_request = ParsedUserDecryptionRequest::new(
                None, // No signature is needed here because we're testing response validation
                alloy_primitives::Address::from_public_key(bad_client_vk.pk()),
                enc_key_buf,
                vec![CiphertextHandle::new(ciphertext_handle.clone())],
                dummy_domain.verifying_contract.unwrap(),
            );
            assert!(validate_user_decrypt_responses_against_request(
                &server_addresses,
                &bad_client_request,
                &dummy_domain,
                &agg_resp,
            )
            .unwrap()
            .is_none());
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(
                validate_user_decrypt_responses_against_request(
                    &server_addresses,
                    &client_request,
                    &dummy_domain,
                    &agg_resp,
                )
                .unwrap()
                .unwrap()
                .len(),
                2
            );
        }
    }

    #[test]
    fn test_select_most_common_user_dec() {
        let digest = vec![1, 2, 3, 4];
        let ciphertext_handle = vec![5, 6, 7, 8];
        let resp0 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: vec![],
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 1,
            };
            UserDecryptionResponse {
                signature: vec![],
                external_signature: vec![],
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        // two responses, second response has modified packing_factor
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.signcrypted_ciphertexts[0].packing_factor = 2);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(select_most_common_user_dec(2, &agg_resp), None);
        }

        // two responses, second response has modified fhe_type
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.signcrypted_ciphertexts[0].fhe_type = 2);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(select_most_common_user_dec(2, &agg_resp), None);
        }

        // two responses, second response has modified handle
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.signcrypted_ciphertexts[0].external_handle = vec![42]);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(select_most_common_user_dec(2, &agg_resp), None);
        }

        // two responses, second response has modified degree
        {
            let mut resp1 = resp0.clone();
            resp1.payload.iter_mut().for_each(|x| x.degree = 2);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(select_most_common_user_dec(2, &agg_resp), None);
        }

        // two responses, second response has modified digest
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.digest = vec![9, 9, 9, 9]);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(select_most_common_user_dec(2, &agg_resp), None);
        }

        // two responses, no modification
        {
            let resp1 = resp0.clone();
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(
                select_most_common_user_dec(2, &agg_resp),
                resp0.payload.clone()
            );
        }

        let resp1 = resp0.clone();

        // resp2 is different from resp0 and resp1
        let resp2 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: vec![],
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: 1,
                    signcrypted_ciphertext: vec![],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 2, // degree is different
            };
            UserDecryptionResponse {
                signature: vec![],
                external_signature: vec![],
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        // three responses, but does not exceed threshold, we should have None
        {
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];
            assert_eq!(select_most_common_user_dec(3, &agg_resp), None);
        }

        // three responses where the second response is modified field that's unrelated to the hashmap key
        {
            let mut resp1 = resp1.clone();
            resp1.external_signature = vec![1, 2, 3, 4];
            let agg_resp = vec![resp0.clone(), resp1, resp2.clone()];
            assert_eq!(
                select_most_common_user_dec(2, &agg_resp),
                resp0.payload.clone()
            );
        }
    }
}
