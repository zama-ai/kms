use crate::anyhow_error_and_log;
use crate::client::client_wasm::Client;
use crate::consts::{SIGNING_KEY_ID, signing_material_id};
use crate::cryptography::signing::{SigningSchemeType, UnifiedPublicSigKey};
use crate::engine::validation::{
    ExpectedSigner, ResponseSignatures, SignedPayloads, verify_response_signatures,
};
use crate::vault::storage::{
    Storage, StorageReader,
    crypto_material::{get_client_signing_key, get_client_verification_key, read_verf_key_at},
};
use alloy_dyn_abi::Eip712Domain;
use alloy_sol_types::SolStruct;
use futures_util::future::{TryFutureExt, try_join_all};
use hashing::DomainSep;
use itertools::Itertools;
use kms_grpc::kms::v1::TypedSignature;
use kms_grpc::rpc_types::PubDataType;
use std::collections::HashMap;
use std::fmt;
use strum::IntoEnumIterator;
use threshold_execution::endpoints::decryption::DecryptionMode;
use threshold_execution::tfhe_internals::parameters::DKGParams;

/// Client data type
///
/// Enum which represents the different kinds of public information that can be stored as part of key generation.
/// In practice this means the CRS and different types of public keys.
/// Data of this type is supposed to be readable by anyone on the internet
/// and stored on a medium that _may_ be susceptible to malicious modifications.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClientDataType {
    SigningKey, // Type of the client's signing key
    VerfKey,    // Type for the servers verification keys
}

impl fmt::Display for ClientDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClientDataType::SigningKey => write!(f, "SigningKey"),
            ClientDataType::VerfKey => write!(f, "VerfKey"),
        }
    }
}

impl Client {
    /// Helper method to create a client based on a specific type of storage for loading the keys.
    /// Observe that this method is decoupled from the [Client] to ensure wasm compliance as wasm cannot handle
    /// file reading or generic traits.
    ///
    /// * `client_storage` - the storage where the client's keys (for signing and verifying) are stored.
    /// * `pub_storages` - the storages where the public verification keys of the servers are stored. These must be unique.
    /// * `params` - the FHE parameters
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    pub async fn new_client<ClientS: Storage, PubS: StorageReader>(
        client_storage: ClientS,
        pub_storages: HashMap<u32, PubS>,
        params: &DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> anyhow::Result<Client> {
        let verf_key_type = PubDataType::VerfKey.to_string();
        let pks = try_join_all(pub_storages.iter().map(|(party_id, cur_storage)| {
            cur_storage
                .read_data(&SIGNING_KEY_ID, &verf_key_type)
                .map_ok(move |pk| (*party_id, pk))
        }))
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();

        let pks_unique_count = pks.values().unique().count();

        if pks_unique_count != pks.len() {
            return Err(anyhow_error_and_log(format!(
                "Duplicate public keys present in map: {} unique, {} total",
                pks_unique_count,
                pks.len()
            )));
        }

        let client_pk = get_client_verification_key(&client_storage).await?;
        let client_sk = get_client_signing_key(&client_storage).await?;

        let mut scheme_verf_keys = HashMap::new();
        for (party_id, cur_storage) in pub_storages.iter() {
            scheme_verf_keys.insert(*party_id, read_scheme_verf_keys(cur_storage).await?);
        }

        Ok(Client::new(
            pks,
            scheme_verf_keys,
            client_pk.address(),
            Some(client_sk),
            *params,
            decryption_mode,
        ))
    }

    /// Verify every signature a result carries, and identify the party that produced it.
    ///
    /// A keygen, CRS or preprocessing result carries no deprecated *scalar* signature —
    /// only a decryption response does — so that field is left empty here.
    ///
    /// # Errors
    ///
    /// Fails when nothing about the result can be authenticated, when an entry names a
    /// scheme this client holds no key for, when an entry does not verify, when the
    /// entries do not agree on one party, and when a requested scheme ends up unverified.
    pub fn verify_result_signatures<T: SolStruct>(
        &self,
        signatures: &[TypedSignature],
        external_signature: &[u8],
        sol_type: &T,
        domain: &Eip712Domain,
        dsep: &DomainSep,
        payload_bytes: &[u8],
    ) -> anyhow::Result<(u32, alloy_primitives::Address)> {
        if signatures.is_empty() && external_signature.is_empty() {
            return Err(anyhow_error_and_log(
                "the response carries no signatures and no legacy external signature".to_string(),
            ));
        }
        let addresses = self.get_server_addrs();
        verify_response_signatures(
            &ResponseSignatures {
                scalar: &[],
                external: external_signature,
                list: signatures,
            },
            &SignedPayloads {
                dsep,
                scalar_bytes: &[],
                payload_bytes,
                eip712_hash: Some(sol_type.eip712_signing_hash(domain)),
            },
            &self.signing_schemes,
            &ExpectedSigner::Discover {
                addresses: &addresses,
            },
            &self.scheme_verf_keys,
        )
        .inspect_err(|e| tracing::error!("{e}"))
    }
}

/// Every scheme's verification key stored.
async fn read_scheme_verf_keys<S: StorageReader>(
    storage: &S,
) -> anyhow::Result<HashMap<SigningSchemeType, UnifiedPublicSigKey>> {
    let data_type = PubDataType::TypedVerfKey.to_string();
    let mut keys = HashMap::new();
    for scheme in SigningSchemeType::iter() {
        let req_id = signing_material_id(scheme);
        if !storage.data_exists(&req_id, &data_type).await? {
            continue;
        }
        let verf_key = read_verf_key_at(storage, &req_id, PubDataType::TypedVerfKey, scheme)
            .await
            .map_err(|e| {
                anyhow_error_and_log(format!(
                    "Failed to read the {scheme} verification key from \"{}\": {e}",
                    storage.info()
                ))
            })?;
        keys.insert(scheme, verf_key);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::{
        NodeSigningIdentity, RootSigningSeed, compute_eip712_signature, gen_sig_keys,
    };
    use crate::dummy_domain;
    use aes_prng::AesRng;
    use kms_grpc::RequestId;
    use kms_grpc::solidity_types::CrsgenVerification;
    use rand::SeedableRng;

    const DSEP: &DomainSep = b"CLNTTEST";
    const PARTY: u32 = 1;
    const PAYLOAD: &[u8] = b"the serialized result payload a non-ECDSA scheme signs";

    fn seeded_identity(seed: u64) -> NodeSigningIdentity {
        let mut rng = AesRng::seed_from_u64(seed);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        NodeSigningIdentity::new(sk, RootSigningSeed::random(&mut rng))
    }

    /// The result the ECDSA entry of every test signature list covers.
    fn sol_type() -> CrsgenVerification {
        CrsgenVerification::new(&RequestId::zeros(), 64, vec![7u8; 32], vec![])
    }

    /// A client that knows `identity` as party [`PARTY`], with or without that
    /// party's per-scheme verification keys.
    fn client_for(identity: &NodeSigningIdentity, with_scheme_keys: bool) -> Client {
        let scheme_verf_keys = if with_scheme_keys {
            let keys = SigningSchemeType::iter()
                .map(|scheme| (scheme, identity.unified_verifying_key(scheme).unwrap()))
                .collect();
            HashMap::from([(PARTY, keys)])
        } else {
            HashMap::new()
        };
        Client::new(
            HashMap::from([(PARTY, identity.verf_key())]),
            scheme_verf_keys,
            identity.verf_key().address(),
            None,
            crate::consts::TEST_PARAM,
            None,
        )
    }

    fn client_requesting(
        identity: &NodeSigningIdentity,
        with_scheme_keys: bool,
        schemes: &[SigningSchemeType],
    ) -> Client {
        let mut client = client_for(identity, with_scheme_keys);
        client.set_signing_schemes(schemes).unwrap();
        client
    }

    /// The signatures `identity` produces for `schemes` over `payload`, in the
    /// forms `engine::base::scheme_signing_jobs` defines.
    fn signatures_for(
        identity: &NodeSigningIdentity,
        schemes: &[SigningSchemeType],
        payload: &[u8],
    ) -> Vec<TypedSignature> {
        let domain = dummy_domain();
        schemes
            .iter()
            .map(|&scheme| {
                let signature = match scheme {
                    SigningSchemeType::Ecdsa256k1 => {
                        compute_eip712_signature(identity.ecdsa(), &sol_type(), &domain).unwrap()
                    }
                    _ => identity
                        .unified_sign_with(scheme, DSEP, payload)
                        .unwrap()
                        .to_bytes(),
                };
                TypedSignature {
                    scheme: scheme.as_wire(),
                    signature,
                }
            })
            .collect()
    }

    fn verify(
        client: &Client,
        signatures: &[TypedSignature],
        payload: &[u8],
    ) -> anyhow::Result<(u32, alloy_primitives::Address)> {
        // No legacy signature is offered: these cases are about the list itself.
        verify_with_legacy(client, signatures, &[], payload)
    }

    fn verify_with_legacy(
        client: &Client,
        signatures: &[TypedSignature],
        external_signature: &[u8],
        payload: &[u8],
    ) -> anyhow::Result<(u32, alloy_primitives::Address)> {
        client.verify_result_signatures(
            signatures,
            external_signature,
            &sol_type(),
            &dummy_domain(),
            DSEP,
            payload,
        )
    }

    /// The deprecated scalar ECDSA/EIP-712 signature, which is all a node from a
    /// release before `signatures` carries.
    fn legacy_external_signature(identity: &NodeSigningIdentity) -> Vec<u8> {
        compute_eip712_signature(identity.ecdsa(), &sol_type(), &dummy_domain()).unwrap()
    }

    /// Every entry verifies, and the result is attributed to the signing party.
    #[test]
    fn every_scheme_of_a_result_verifies() {
        let identity = seeded_identity(1);
        let every_scheme: Vec<_> = SigningSchemeType::iter().collect();
        // Ask for every scheme, so every entry is one the verifier has to check rather
        // than one it may pass over as unrequested.
        let client = client_requesting(&identity, true, &every_scheme);
        let signatures = signatures_for(&identity, &every_scheme, PAYLOAD);

        let (party_id, address) = verify(&client, &signatures, PAYLOAD).unwrap();
        assert_eq!(party_id, PARTY);
        assert_eq!(address, identity.verf_key().address());
    }

    /// A result with nothing to check at all must not pass: no list, and no legacy
    /// signature to fall back on either.
    #[test]
    fn a_result_with_no_signature_at_all_is_rejected() {
        let identity = seeded_identity(2);
        let client = client_for(&identity, true);

        let err = verify(&client, &[], PAYLOAD).unwrap_err().to_string();
        assert!(
            err.contains("carries no signatures"),
            "the error does not name the cause: {err}"
        );
    }

    /// The rolling-upgrade case: a node from a release before `signatures` answers with
    /// an empty list and the legacy ECDSA signature alone, and that still authenticates
    /// the result for a client asking only for ECDSA.
    #[test]
    fn an_empty_list_falls_back_to_the_legacy_signature() {
        let identity = seeded_identity(12);
        let client = client_for(&identity, true);

        let (party_id, address) =
            verify_with_legacy(&client, &[], &legacy_external_signature(&identity), PAYLOAD)
                .unwrap();
        assert_eq!(party_id, PARTY);
        assert_eq!(address, identity.verf_key().address());
    }

    /// The fallback counts for ECDSA only. An old node cannot produce a post-quantum
    /// signature, so a request that named one is not satisfied by its legacy signature —
    /// otherwise any server could drop a requested scheme and still be accepted.
    #[test]
    fn the_legacy_fallback_does_not_satisfy_a_post_quantum_request() {
        let identity = seeded_identity(13);
        let client = client_requesting(
            &identity,
            true,
            &[SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65],
        );

        let err = verify_with_legacy(&client, &[], &legacy_external_signature(&identity), PAYLOAD)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("MlDsa65") && err.contains("was requested"),
            "the error does not name the unanswered scheme: {err}"
        );
    }

    /// The fallback is a real signature check, not a waiver for an empty list.
    #[test]
    fn the_legacy_fallback_rejects_a_signature_of_another_party() {
        let identity = seeded_identity(14);
        let client = client_for(&identity, true);
        let stranger = legacy_external_signature(&seeded_identity(15));

        assert!(verify_with_legacy(&client, &[], &stranger, PAYLOAD).is_err());
        assert!(verify_with_legacy(&client, &[], &[0u8; 65], PAYLOAD).is_err());
    }

    /// The legacy signature is checked *alongside* the list, not instead of it. A result
    /// whose list verifies but whose deprecated field does not is still rejected: the two
    /// are independent statements about the same result, and they have to agree.
    #[test]
    fn a_bad_legacy_signature_is_rejected_even_when_the_list_verifies() {
        let identity = seeded_identity(16);
        let client = client_for(&identity, true);
        let signatures = signatures_for(&identity, &[SigningSchemeType::Ecdsa256k1], PAYLOAD);

        // Both copies present and agreeing is the honest case.
        let (party_id, _address) = verify_with_legacy(
            &client,
            &signatures,
            &legacy_external_signature(&identity),
            PAYLOAD,
        )
        .unwrap();
        assert_eq!(party_id, PARTY);

        // A garbage legacy signature is a rejection, and so is one of another party.
        assert!(verify_with_legacy(&client, &signatures, &[0xAA; 65], PAYLOAD).is_err());
        assert!(
            verify_with_legacy(
                &client,
                &signatures,
                &legacy_external_signature(&seeded_identity(17)),
                PAYLOAD,
            )
            .is_err()
        );
    }

    /// A MlDsa65 signature is attributed to the correct signing party, provided
    /// MlDsa65 is what the client asked for.
    #[test]
    fn a_result_without_an_ecdsa_entry_is_attributed() {
        let identity = seeded_identity(3);
        let client = client_requesting(&identity, true, &[SigningSchemeType::MlDsa65]);
        let signatures = signatures_for(&identity, &[SigningSchemeType::MlDsa65], PAYLOAD);

        let (party_id, _address) = verify(&client, &signatures, PAYLOAD).unwrap();
        assert_eq!(party_id, PARTY);
    }

    /// The same list is rejected by a client that asked for ECDSA: a server may
    /// not answer with a scheme of its own choosing.
    #[test]
    fn a_result_missing_the_requested_ecdsa_entry_is_rejected() {
        let identity = seeded_identity(3);
        let client = client_for(&identity, true);
        let signatures = signatures_for(&identity, &[SigningSchemeType::MlDsa65], PAYLOAD);

        let err = verify(&client, &signatures, PAYLOAD)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("was requested"),
            "the error does not name the missing scheme: {err}"
        );
    }

    /// Each entry covers the payload it was signed over, and nothing else.
    #[test]
    fn a_tampered_payload_is_rejected() {
        let identity = seeded_identity(4);

        for scheme in SigningSchemeType::iter().filter(|s| *s != SigningSchemeType::Ecdsa256k1) {
            // Ask for exactly the scheme under test, so the rejection can only come
            // from the signature check and not from a scheme left unverified.
            let client = client_requesting(&identity, true, &[scheme]);
            let signatures = signatures_for(&identity, &[scheme], PAYLOAD);
            assert!(
                verify(&client, &signatures, b"a different payload").is_err(),
                "the {scheme} entry verified a payload it does not cover"
            );
        }
    }

    /// Another party's signatures are not accepted as this party's.
    #[test]
    fn another_partys_signatures_are_rejected() {
        let identity = seeded_identity(5);
        let client = client_for(&identity, true);
        let signatures = signatures_for(
            &seeded_identity(6),
            &SigningSchemeType::iter().collect::<Vec<_>>(),
            PAYLOAD,
        );

        assert!(verify(&client, &signatures, PAYLOAD).is_err());
    }

    /// A signature that cannot be checked for want of a key must not pass for one
    /// that was checked.
    #[test]
    fn an_entry_with_no_known_key_is_rejected() {
        let identity = seeded_identity(7);
        let every_scheme: Vec<_> = SigningSchemeType::iter().collect();
        // The client holds no per-scheme keys, but asks for every scheme, so each entry
        // is one it is obliged to check and cannot.
        let client = client_requesting(&identity, false, &every_scheme);
        let signatures = signatures_for(&identity, &every_scheme, PAYLOAD);

        let err = verify(&client, &signatures, PAYLOAD)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("verification key") || err.contains("no known party key"),
            "the error does not name the missing key: {err}"
        );
    }

    /// Entries have to agree on one signing party.
    #[test]
    fn mixed_party_entries_are_rejected() {
        let identity = seeded_identity(8);
        let other = seeded_identity(9);
        let requested = [SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65];
        let client = client_requesting(&identity, true, &requested);

        let mut signatures = signatures_for(&identity, &[SigningSchemeType::Ecdsa256k1], PAYLOAD);
        signatures.extend(signatures_for(
            &other,
            &[SigningSchemeType::MlDsa65],
            PAYLOAD,
        ));

        assert!(verify(&client, &signatures, PAYLOAD).is_err());
    }

    /// A hybrid request answered with its ECDSA half alone is rejected, even though that half verifies.
    #[test]
    fn a_hybrid_request_answered_with_ecdsa_alone_is_rejected() {
        let identity = seeded_identity(11);
        let requested = [SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65];
        let client = client_requesting(&identity, true, &requested);
        let ecdsa_only = signatures_for(&identity, &[SigningSchemeType::Ecdsa256k1], PAYLOAD);

        let err = verify(&client, &ecdsa_only, PAYLOAD)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("MlDsa65") && err.contains("was requested"),
            "the error does not name the dropped post-quantum scheme: {err}"
        );

        // The full list, by contrast, passes.
        let both = signatures_for(&identity, &requested, PAYLOAD);
        let (party_id, _address) = verify(&client, &both, PAYLOAD).unwrap();
        assert_eq!(party_id, PARTY);
    }

    /// A response that drops any one requested scheme is caught, even though every
    /// entry it does carry verifies.
    #[test]
    fn a_stripped_scheme_is_caught() {
        let identity = seeded_identity(10);
        let requested: Vec<_> = SigningSchemeType::iter().collect();
        let client = client_requesting(&identity, true, &requested);
        let signatures = signatures_for(&identity, &requested, PAYLOAD);

        verify(&client, &signatures, PAYLOAD).unwrap();

        for dropped in SigningSchemeType::iter() {
            let stripped: Vec<_> = signatures
                .iter()
                .filter(|typed| {
                    SigningSchemeType::try_from(typed.scheme).is_ok_and(|found| found != dropped)
                })
                .cloned()
                .collect();
            let err = verify(&client, &stripped, PAYLOAD).unwrap_err().to_string();
            assert!(
                err.contains(&dropped.to_string()),
                "a response missing its {dropped} signature was not rejected for that: {err}"
            );
        }
    }
}
