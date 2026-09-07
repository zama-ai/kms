use crate::anyhow_error_and_log;
use crate::client::client_wasm::Client;
use crate::consts::{SIGNING_KEY_ID, signing_material_id};
use crate::cryptography::signatures::recover_address_from_ext_signature;
use crate::cryptography::signing::{
    Signature, SigningSchemeType, UnifiedPublicSigKey, unified_verify,
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

    /// The party whose ECDSA identity produced `external_signature`, if it is one of
    /// servers this client is aware of.
    pub(crate) fn find_verifying_party<T: SolStruct>(
        &self,
        data: &T,
        domain: &Eip712Domain,
        external_signature: &[u8],
    ) -> Option<(u32, alloy_primitives::Address)> {
        let addr = match recover_address_from_ext_signature(data, domain, external_signature) {
            Ok(a) => a,
            Err(_) => {
                tracing::error!("Could not recover address from signature");
                return None;
            }
        };

        self.get_server_addrs()
            .into_iter()
            .find(|(_party_id, verf_key)| *verf_key == addr)
    }

    /// Verify every signature a result carries, and identify the party that produced it.
    ///
    /// # Errors
    ///
    /// Fails when `signatures` is empty, when an entry names a scheme this client holds no
    /// key for, when an entry does not verify, when the entries do not agree
    /// on one party, and when a requested scheme is missing from the list.
    pub fn verify_result_signatures<T: SolStruct>(
        &self,
        signatures: &[TypedSignature],
        sol_type: &T,
        domain: &Eip712Domain,
        dsep: &DomainSep,
        payload_bytes: &[u8],
    ) -> anyhow::Result<(u32, alloy_primitives::Address)> {
        if signatures.is_empty() {
            return Err(anyhow_error_and_log(
                "the response carries no signatures".to_string(),
            ));
        }
        Self::ensure_requested_schemes_present(signatures, &self.signing_schemes)?;

        let mut signer: Option<(u32, alloy_primitives::Address)> = None;
        for typed in signatures {
            let scheme = SigningSchemeType::try_from(typed.scheme).map_err(|e| {
                anyhow_error_and_log(format!(
                    "the response carries a signature of an unknown scheme: {e}"
                ))
            })?;
            let found = match scheme {
                // Recoverable, and therefore the identity anchor.
                SigningSchemeType::Ecdsa256k1 => self
                    .find_verifying_party(sol_type, domain, &typed.signature)
                    .ok_or_else(|| {
                        anyhow_error_and_log(
                            "the ECDSA signature of the response belongs to no known party"
                                .to_string(),
                        )
                    })?,
                _ => {
                    let signature = Signature::new(scheme, typed.signature.clone());
                    self.verify_against_scheme_key(scheme, &signature, dsep, payload_bytes, signer)?
                }
            };
            match signer {
                Some((party, _)) if party != found.0 => {
                    return Err(anyhow_error_and_log(format!(
                        "the response mixes signatures of party {party} and party {}",
                        found.0
                    )));
                }
                _ => signer = Some(found),
            }
        }

        signer.ok_or_else(|| {
            anyhow_error_and_log("no signature of the response identified a party".to_string())
        })
    }

    /// Verify a non-ECDSA signature and return the party it belongs to.
    fn verify_against_scheme_key(
        &self,
        scheme: SigningSchemeType,
        signature: &Signature,
        dsep: &DomainSep,
        payload_bytes: &[u8],
        signer: Option<(u32, alloy_primitives::Address)>,
    ) -> anyhow::Result<(u32, alloy_primitives::Address)> {
        if let Some((party_id, address)) = signer {
            let verf_key = self
                .scheme_verf_keys
                .get(&party_id)
                .and_then(|keys| keys.get(&scheme))
                .ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "party {party_id} signed under {scheme}, but this client holds no \
                         {scheme} verification key for it"
                    ))
                })?;
            unified_verify(dsep, payload_bytes, signature, verf_key).map_err(|e| {
                anyhow_error_and_log(format!(
                    "the {scheme} signature of party {party_id} did not verify: {e}"
                ))
            })?;
            return Ok((party_id, address));
        }

        let addresses = self.get_server_addrs();
        let attributed = self.scheme_verf_keys.iter().find_map(|(party_id, keys)| {
            let verf_key = keys.get(&scheme)?;
            unified_verify(dsep, payload_bytes, signature, verf_key).ok()?;
            addresses.get(party_id).map(|address| (*party_id, *address))
        });
        attributed.ok_or_else(|| {
            anyhow_error_and_log(format!(
                "the {scheme} signature of the response verifies under no known party key"
            ))
        })
    }

    /// Check that `signatures` covers every scheme that was requested.
    pub fn ensure_requested_schemes_present(
        signatures: &[TypedSignature],
        requested: &[SigningSchemeType],
    ) -> anyhow::Result<()> {
        for &scheme in requested {
            let present = signatures.iter().any(|typed| {
                SigningSchemeType::try_from(typed.scheme).is_ok_and(|found| found == scheme)
            });
            if !present {
                return Err(anyhow_error_and_log(format!(
                    "the response carries no {scheme} signature, but {scheme} was requested"
                )));
            }
        }
        Ok(())
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
        client.signing_schemes = schemes.to_vec();
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
                    scheme: kms_grpc::kms::v1::SigningSchemeType::from(scheme) as i32,
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
        client.verify_result_signatures(signatures, &sol_type(), &dummy_domain(), DSEP, payload)
    }

    /// Every entry verifies, and the result is attributed to the signing party.
    #[test]
    fn every_scheme_of_a_result_verifies() {
        let identity = seeded_identity(1);
        let client = client_for(&identity, true);
        let signatures = signatures_for(
            &identity,
            &SigningSchemeType::iter().collect::<Vec<_>>(),
            PAYLOAD,
        );

        let (party_id, address) = verify(&client, &signatures, PAYLOAD).unwrap();
        assert_eq!(party_id, PARTY);
        assert_eq!(address, identity.verf_key().address());
    }

    /// An empty list of signatures must not pass.
    #[test]
    fn an_empty_list_is_rejected() {
        let identity = seeded_identity(2);
        let client = client_for(&identity, true);

        let err = verify(&client, &[], PAYLOAD).unwrap_err().to_string();
        assert!(
            err.contains("predates"),
            "the error does not name the cause: {err}"
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
            // Ask for exactly the scheme under test, so the rejection can only
            // come from the signature check and not from the presence check.
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
        let client = client_for(&identity, false);
        let signatures = signatures_for(
            &identity,
            &SigningSchemeType::iter().collect::<Vec<_>>(),
            PAYLOAD,
        );

        let err = verify(&client, &signatures, PAYLOAD)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("verification key"),
            "the error does not name the missing key: {err}"
        );
    }

    /// Entries have to agree on one signing party.
    #[test]
    fn mixed_party_entries_are_rejected() {
        let identity = seeded_identity(8);
        let other = seeded_identity(9);
        let client = client_for(&identity, true);

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

    /// A response that drops a requested scheme is caught, while the always
    /// present ECDSA entry needs no separate presence check.
    #[test]
    fn a_stripped_scheme_is_caught() {
        let identity = seeded_identity(10);
        let signatures = signatures_for(
            &identity,
            &SigningSchemeType::iter().collect::<Vec<_>>(),
            PAYLOAD,
        );
        let requested: Vec<_> = SigningSchemeType::iter().collect();

        Client::ensure_requested_schemes_present(&signatures, &requested).unwrap();

        for dropped in SigningSchemeType::iter().filter(|s| *s != SigningSchemeType::Ecdsa256k1) {
            let stripped: Vec<_> = signatures
                .iter()
                .filter(|typed| {
                    SigningSchemeType::try_from(typed.scheme).is_ok_and(|found| found != dropped)
                })
                .cloned()
                .collect();
            assert!(
                Client::ensure_requested_schemes_present(&stripped, &requested).is_err(),
                "a response missing its {dropped} signature was accepted"
            );
        }
    }
}
