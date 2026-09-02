//! Verification of material in private and public storage.
//!
//! Public storage may deviate from a consistent state: a misconfigured bucket or prefix can
//! point a node at the wrong material, and writes are not atomic, so a crash part-way through
//! an operation can leave an entry missing, truncated, or stale. Private storage holds the
//! digests and signatures that say what the published material should be, so it is the
//! reference, and every integrity check here runs in that direction — an expected value is
//! taken from private storage and compared against what public storage holds, never the other
//! way around.
//!
//! Three rules govern everything here:
//!
//! 1. **Private storage is the reference.** Every integrity check takes an expected value from
//!    private storage and looks up its counterpart in public storage, never the other way
//!    around.
//! 2. **Extra material in public storage is reported, never rejected.** Some of it is
//!    legitimate: a retired keyset, or leftovers from a previous deployment that shares the
//!    bucket. Some of it is not: a write that failed half-way, a corrupted store, or an entry
//!    planted by someone with write access to the storage. The node cannot tell these apart, so
//!    once the integrity checks pass, [`report_unexpected_public_material`] lists public storage
//!    and logs an error for every entry that private storage does not account for.
//! 3. **Read-only.** Nothing here writes to, repairs, or re-fetches public storage.
//!
//! Startup verification operates on raw stored bytes. It never deserializes stored keys or
//! CRSes: current material is checked by hashing those bytes, while legacy material (which has
//! no digest) is checked for presence only.

use crate::backup::operator::RecoveryValidationMaterial;
use crate::consts::{SIGNING_KEY_ID, signing_material_id};
use crate::cryptography::signatures::recover_address_from_ext_signature;
use crate::cryptography::signing::SigningSchemeType;
use crate::cryptography::signing::ecdsa::{PrivateSigKey, PublicSigKey};
use crate::engine::base::{
    CrsGenMetadata, CrsGenMetadataInner, CurrentPublicMaterialLayout, DSEP_PUBDATA_KEY,
    KeyGenMetadata, KeyGenMetadataInner, StoredEip712Domain, classify_current_public_material,
    crs_sol_type, keygen_sol_type,
};
use crate::engine::material_integrity::{
    verify_compressed_key_digest_from_bytes, verify_crs_digest_from_bytes,
    verify_public_key_digest_from_bytes, verify_server_key_digest_from_bytes,
};
use crate::vault::storage::{StorageReader, read_text_at_request_id};
use alloy_primitives::Address;
use alloy_sol_types::{Eip712Domain, SolStruct};
use kms_grpc::RequestId;
use kms_grpc::rpc_types::PubDataType;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use strum::IntoEnumIterator;

const ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE: &str = "Invalid legacy public key metadata shape";
pub(crate) const ERR_METADATA_ID_MISMATCH: &str =
    "Result metadata is stored under a different ID than it declares";
pub(crate) const ERR_VERF_KEY_MISMATCH: &str =
    "Verification key in public storage does not match the private signing key";
pub(crate) const ERR_VERF_ADDRESS_MISMATCH: &str =
    "Verification address in public storage does not match the private signing key";
const ERR_UNEXPECTED_PUBLIC_MATERIAL: &str = "Unexpected public material";
const ERR_UNKNOWN_PUBLIC_DATA_TYPE: &str = "Unexpected data type in public storage";
const ERR_UNLISTABLE_PUBLIC_MATERIAL: &str = "Could not list public material";

fn validate_legacy_public_material_shape<T>(
    public_materials: &HashMap<PubDataType, T>,
) -> anyhow::Result<()> {
    let has_public_key = public_materials.contains_key(&PubDataType::PublicKey);
    let has_server_key = public_materials.contains_key(&PubDataType::ServerKey);

    if has_public_key && has_server_key && public_materials.len() == 2 {
        return Ok(());
    }

    anyhow::bail!(
        "{ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE}: expected exactly {{PublicKey, ServerKey}}, got {:?}",
        public_materials.keys().collect::<Vec<_>>()
    );
}

/// Load the raw bytes of one public material entry, failing with a message that names both
/// the missing entry and the reason on its own.
///
/// Digests are always checked against these raw bytes rather than against a serialization of a
/// decoded value: a tfhe format change since the material was generated would otherwise alter
/// the bytes and report intact material as corrupt.
async fn load_public_bytes<S: StorageReader + Sync>(
    storage: &S,
    id: &RequestId,
    data_type: PubDataType,
) -> anyhow::Result<Vec<u8>> {
    storage
        .load_bytes(id, &data_type.to_string())
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "missing or unreadable public material {data_type} for id={id} in storage \"{}\": {e}",
                storage.info()
            )
        })
}

/// Load raw bytes from storage and verify their digests against the expected values
/// in `key_digest_map`. Returns an error if any digest does not match.
async fn verify_fhe_key_digests<S: StorageReader + Sync>(
    storage: &S,
    id: &RequestId,
    key_digest_map: &BTreeMap<PubDataType, Vec<u8>>,
) -> anyhow::Result<()> {
    let layout = classify_current_public_material(key_digest_map)?;
    let expected_public_key_digest = key_digest_map
        .get(&PubDataType::PublicKey)
        .ok_or_else(|| anyhow::anyhow!("missing digest for public key, id={id}"))?;
    let public_key_bytes = load_public_bytes(storage, id, PubDataType::PublicKey).await?;
    verify_public_key_digest_from_bytes(&public_key_bytes, expected_public_key_digest)?;

    match layout {
        CurrentPublicMaterialLayout::Standard => {
            let server_key_bytes = load_public_bytes(storage, id, PubDataType::ServerKey).await?;
            let expected_server_key_digest = key_digest_map
                .get(&PubDataType::ServerKey)
                .ok_or_else(|| anyhow::anyhow!("missing digest for server key, id={id}"))?;
            verify_server_key_digest_from_bytes(&server_key_bytes, expected_server_key_digest)
        }
        CurrentPublicMaterialLayout::Compressed => {
            let compressed_keyset_bytes =
                load_public_bytes(storage, id, PubDataType::CompressedXofKeySet).await?;
            let expected_compressed_keyset_digest = key_digest_map
                .get(&PubDataType::CompressedXofKeySet)
                .ok_or_else(|| {
                    anyhow::anyhow!("missing digest for compressed xof keyset, id={id}")
                })?;
            verify_compressed_key_digest_from_bytes(
                &compressed_keyset_bytes,
                expected_compressed_keyset_digest,
            )
        }
    }
}

/// Check that the public objects described by legacy metadata are present and readable as raw
/// bytes. Legacy metadata has no digest, so no integrity check is possible, but startup must not
/// deserialize these non-production compatibility objects.
async fn check_legacy_keyset_presence<S: StorageReader + Sync, T>(
    storage: &S,
    id: &RequestId,
    public_materials: &HashMap<PubDataType, T>,
) -> anyhow::Result<()> {
    validate_legacy_public_material_shape(public_materials)?;

    for data_type in [PubDataType::PublicKey, PubDataType::ServerKey] {
        load_public_bytes(storage, id, data_type).await?;
    }

    Ok(())
}

/// Verify the public objects described by private keyset metadata.
///
/// Current metadata is verified by digest; legacy metadata has no digest and is checked only
/// for the presence of its raw public objects.
async fn verify_keysets<S>(
    public_storage: &S,
    entries: &[(RequestId, KeyGenMetadata)],
) -> anyhow::Result<()>
where
    S: StorageReader + Sync,
{
    for (id, metadata) in entries {
        match metadata {
            KeyGenMetadata::Current(inner) => {
                verify_fhe_key_digests(public_storage, id, &inner.key_digest_map).await?;
            }
            KeyGenMetadata::LegacyV0(hash_map) => {
                tracing::info!(
                    "Legacy metadata for id={id}, checking raw object presence only (no digest verification)"
                );
                check_legacy_keyset_presence(public_storage, id, hash_map).await?;
            }
        }
    }
    Ok(())
}

/// Verify the public objects described by private CRS metadata.
///
/// Current metadata is verified by digest; legacy metadata has no digest and is checked only
/// for the presence of its raw public object.
async fn verify_crses<S>(
    public_storage: &S,
    crs_entries: &HashMap<RequestId, CrsGenMetadata>,
) -> anyhow::Result<()>
where
    S: StorageReader + Sync,
{
    for (id, metadata) in crs_entries {
        match metadata {
            CrsGenMetadata::Current(inner) => {
                let crs_bytes = load_public_bytes(public_storage, id, PubDataType::CRS).await?;
                verify_crs_digest_from_bytes(&crs_bytes, &inner.crs_digest)?;
            }
            CrsGenMetadata::LegacyV0(_) => {
                tracing::info!(
                    "Legacy CRS metadata for id={id}, checking raw object presence only (no digest verification)"
                );
                load_public_bytes(public_storage, id, PubDataType::CRS).await?;
            }
        }
    }
    Ok(())
}

/// Verify all recovery validation material loaded from public storage against the node's private
/// signing key. Recovery mode deliberately does not call this helper: its verification key came
/// from public storage and would not provide an independent trust root.
fn verify_recovery_material(
    validation_material: &HashMap<RequestId, RecoveryValidationMaterial>,
    signing_key: &PrivateSigKey,
) -> anyhow::Result<()> {
    let verf_key = PublicSigKey::from_sk(signing_key);
    for (context_id, material) in validation_material {
        if !material.validate(&verf_key) {
            anyhow::bail!("Invalid recovery validation material for context ID {context_id}");
        }
    }
    Ok(())
}

/// Verify the consistency of private storage and then verify the public storage
/// material against private storage, as well as the recovery validation
/// material.
///
/// Once every check passes, public storage is swept for material that private storage does not
/// account for. The sweep logs errors but never fails; see [`report_unexpected_public_material`].
///
/// `key_entries` is a slice rather than a map because the callers list a keyset once per epoch
/// it is stored under. One key ID can therefore appear more than once, and every occurrence is
/// checked.
///
/// Returns the sweep report so callers and tests can inspect the same single scan that startup
/// performs.
pub async fn verify_storage_material<S>(
    public_storage: &S,
    key_entries: &[(RequestId, KeyGenMetadata)],
    crs_entries: &HashMap<RequestId, CrsGenMetadata>,
    recovery_material: &HashMap<RequestId, RecoveryValidationMaterial>,
    signing_key: &PrivateSigKey,
) -> anyhow::Result<UnexpectedPublicMaterial>
where
    S: StorageReader + Sync,
{
    // Every metadata entry must declare the ID it is stored under before anything else uses it.
    // Otherwise metadata filed under the wrong ID could pass whenever the bytes published under
    // that ID happen to match its digests.
    for (key_id, metadata) in key_entries {
        ensure_keygen_metadata_id_matches(key_id, metadata)?;
    }
    for (crs_id, metadata) in crs_entries {
        ensure_crs_metadata_id_matches(crs_id, metadata)?;
    }

    let expected_address = PublicSigKey::from_sk(signing_key).address();
    verify_private_metadata(key_entries, crs_entries, expected_address)?;

    for data_type in PubDataType::iter() {
        match data_type {
            PubDataType::PublicKey => {
                // Verifies PublicKey, ServerKey, and CompressedXofKeySet together.
                verify_keysets(public_storage, key_entries).await?;
            }
            PubDataType::CRS => {
                verify_crses(public_storage, crs_entries).await?;
            }
            #[allow(deprecated)]
            PubDataType::VerfKey => {
                // Verifies both the legacy verification key and address together.
                verify_signing_key_material(public_storage, signing_key).await?;
            }
            PubDataType::RecoveryMaterial => {
                verify_recovery_material(recovery_material, signing_key)?;
            }
            PubDataType::ServerKey
            | PubDataType::DecompressionKey
            | PubDataType::CACert
            | PubDataType::CompressedXofKeySet
            | PubDataType::TypedVerfKey
            | PubDataType::TypedVerfAddress => {
                // ServerKey and CompressedXofKeySet are checked by verify_keysets above.
                // CACert is done during certificate loading.
                // DecompressionKey is not used in production at the moment and it does not have a private component.
                //
                // TODO(https://github.com/zama-ai/kms-internal/issues/3078)
                // The remaining types (TypedVerfKey, TypedVerfAddress) will be done later
            }
            #[allow(deprecated)]
            PubDataType::VerfAddress | PubDataType::PublicKeyMetadata => {
                // VerfAddress is checked by verify_signing_key_material above. PublicKeyMetadata
                // is deprecated and no longer stored.
            }
        }
    }

    let unexpected = report_unexpected_public_material(
        public_storage,
        key_entries,
        crs_entries,
        recovery_material,
    )
    .await;

    tracing::info!(
        "Verified storage material in storage \"{}\": {} keyset(s), {} CRS(es), {} recovery validation material item(s), {} unexpected public entry(ies)",
        public_storage.info(),
        key_entries.len(),
        crs_entries.len(),
        recovery_material.len(),
        unexpected.unexpected_count()
    );
    Ok(unexpected)
}

/// Verify the signatures that authenticate current metadata in private storage.
///
/// We cannot authenticate the signatures for older metadata since the EIP-712
/// domain was not persisted. So those entries remain usable for backward
/// compatibility. All newly written current metadata must carry a domain and a
/// valid signature from this node.
///
/// Assumes every entry has already been checked against the ID it is stored under; see
/// [`verify_keygen_metadata_signature`] for why that ordering matters.
fn verify_private_metadata(
    key_entries: &[(RequestId, KeyGenMetadata)],
    crs_entries: &HashMap<RequestId, CrsGenMetadata>,
    expected_address: Address,
) -> anyhow::Result<()> {
    for (key_id, metadata) in key_entries {
        match metadata {
            KeyGenMetadata::Current(inner) => {
                verify_keygen_metadata_signature(key_id, inner, expected_address)?;
            }
            KeyGenMetadata::LegacyV0(_) => {
                tracing::info!(
                    "Legacy keygen metadata for id={key_id} has no stored EIP-712 domain; skipping signature verification"
                );
            }
        }
    }

    for (crs_id, metadata) in crs_entries {
        match metadata {
            CrsGenMetadata::Current(inner) => {
                verify_crs_metadata_signature(crs_id, inner, expected_address)?;
            }
            CrsGenMetadata::LegacyV0(_) => {
                tracing::info!(
                    "Legacy CRS metadata for id={crs_id} has no stored EIP-712 domain; skipping signature verification"
                );
            }
        }
    }

    Ok(())
}

/// Verify the EIP-712 `external_signature` on one current keygen metadata record.
///
/// Callers must run [`ensure_keygen_metadata_id_matches`] first. Without it,
/// metadata stored under the wrong ID would verify happily against the ID it
/// declares and the mismatch would go unnoticed here.
fn verify_keygen_metadata_signature(
    key_id: &RequestId,
    metadata: &KeyGenMetadataInner,
    expected_address: Address,
) -> anyhow::Result<()> {
    // TODO(github.com/zama-ai/kms-internal/issues/3201)
    // After we upgrade to 0.16 (and have migrated keys in 0.15),
    // or after we retire the default epoch, then remove the backward compatibility support.
    // That is, we should always have a domain in the metadata that we can use to verify the signature.
    let Some(stored_domain) = metadata.eip712_domain.as_ref() else {
        tracing::info!(
            "Current keygen metadata for id={key_id} has no stored EIP-712 domain; skipping signature verification"
        );
        return Ok(());
    };

    // Signing sites know their layout statically; here it can only be read back off the
    // stored digest map.
    let sol_type = classify_current_public_material(&metadata.key_digest_map)
        .and_then(|layout| {
            keygen_sol_type(
                layout,
                &metadata.preprocessing_id,
                &metadata.key_id,
                &metadata.key_digest_map,
                metadata.extra_data.as_deref().unwrap_or_default(),
            )
        })
        .map_err(|e| anyhow::anyhow!("Invalid private keygen metadata for id={key_id}: {e}"))?;
    verify_eip712_metadata_signature(
        "keygen",
        key_id,
        &sol_type,
        stored_domain,
        &metadata.external_signature,
        expected_address,
    )?;

    Ok(())
}

/// Verify the EIP-712 `external_signature` on one current CRS metadata record.
///
/// Carries the same precondition as [`verify_keygen_metadata_signature`]: the signed message is
/// rebuilt from the metadata's own `crs_id`, so [`ensure_crs_metadata_id_matches`] must have run
/// over this entry first.
fn verify_crs_metadata_signature(
    crs_id: &RequestId,
    metadata: &CrsGenMetadataInner,
    expected_address: Address,
) -> anyhow::Result<()> {
    // TODO(github.com/zama-ai/kms-internal/issues/3201)
    // After we can retire the default epoch, we can remove the backward compatibility support
    // since new epochs will be re-signed using the more recent format.
    // That is, we should always have a domain in the metadata that we can use to verify the signature.
    let Some(stored_domain) = metadata.eip712_domain.as_ref() else {
        tracing::info!(
            "Current CRS metadata for id={crs_id} has no stored EIP-712 domain; skipping signature verification"
        );
        return Ok(());
    };

    let sol_type = crs_sol_type(
        &metadata.crs_id,
        &metadata.crs_digest,
        metadata.max_num_bits,
        metadata.extra_data.as_deref().unwrap_or_default(),
    );
    verify_eip712_metadata_signature(
        "CRS",
        crs_id,
        &sol_type,
        stored_domain,
        &metadata.external_signature,
        expected_address,
    )
}

fn verify_eip712_metadata_signature<T: SolStruct>(
    metadata_kind: &str,
    metadata_id: &RequestId,
    sol_type: &T,
    stored_domain: &StoredEip712Domain,
    external_signature: &[u8],
    expected_address: Address,
) -> anyhow::Result<()> {
    let domain = Eip712Domain::from(stored_domain);
    let recovered_address = recover_address_from_ext_signature(sol_type, &domain, external_signature)
        .map_err(|e| {
            anyhow::anyhow!(
                "Invalid EIP-712 signature in private {metadata_kind} metadata for id={metadata_id}: {e}"
            )
        })?;
    if recovered_address != expected_address {
        anyhow::bail!(
            "Invalid EIP-712 signature in private {metadata_kind} metadata for id={metadata_id}: recovered signer {recovered_address}, expected {expected_address}"
        );
    }

    // TODO(https://github.com/zama-ai/kms-internal/issues/3078): verify the optional
    // per-scheme signatures stored in the metadata, including PQ signatures.
    Ok(())
}

/// Check that keyset metadata declares the same key ID it is stored under.
fn ensure_keygen_metadata_id_matches(
    key_id: &RequestId,
    metadata: &KeyGenMetadata,
) -> anyhow::Result<()> {
    let KeyGenMetadata::Current(inner) = metadata else {
        return Ok(());
    };
    if inner.key_id != *key_id {
        anyhow::bail!(
            "{ERR_METADATA_ID_MISMATCH}: keygen metadata stored under key_id={key_id} declares \
             key_id={}",
            inner.key_id
        );
    }
    Ok(())
}

/// Check that CRS metadata declares the same CRS ID it is stored under.
///
/// See [`ensure_keygen_metadata_id_matches`].
fn ensure_crs_metadata_id_matches(
    crs_id: &RequestId,
    metadata: &CrsGenMetadata,
) -> anyhow::Result<()> {
    let CrsGenMetadata::Current(inner) = metadata else {
        return Ok(());
    };
    if inner.crs_id != *crs_id {
        anyhow::bail!(
            "{ERR_METADATA_ID_MISMATCH}: CRS metadata stored under crs_id={crs_id} declares \
             crs_id={}",
            inner.crs_id
        );
    }
    Ok(())
}

/// Check that the verification key and Ethereum address published in public storage are the
/// ones derived from the private signing key.
///
/// Both entries are read at [`SIGNING_KEY_ID`] specifically rather than by enumerating the
/// folder, so an unrelated leftover entry under a different ID does not fail this check;
/// [`report_unexpected_public_material`] reports it instead. In particular this must not go
/// through `get_core_verification_key`, which fails unless public storage holds exactly one
/// verification key.
pub async fn verify_signing_key_material<S>(
    public_storage: &S,
    sk: &PrivateSigKey,
) -> anyhow::Result<()>
where
    S: StorageReader + Sync,
{
    let expected_verf_key = PublicSigKey::from_sk(sk);
    let expected_address = expected_verf_key.address();
    let signing_key_id = *SIGNING_KEY_ID;

    let stored_verf_key_bytes =
        load_public_bytes(public_storage, &signing_key_id, PubDataType::VerfKey).await?;
    let expected_verf_key_digest = hashing::hash_versioned(&DSEP_PUBDATA_KEY, &expected_verf_key)
        .map_err(|e| {
        anyhow::anyhow!("failed to hash the verification key derived from private storage: {e}")
    })?;
    verify_public_key_digest_from_bytes(&stored_verf_key_bytes, &expected_verf_key_digest)
        .map_err(|e| {
            anyhow::anyhow!(
                "{ERR_VERF_KEY_MISMATCH}: expected the key for address {}: {e}",
                expected_address
            )
        })?;

    let stored_address_text = read_text_at_request_id(
        public_storage,
        &signing_key_id,
        &PubDataType::VerfAddress.to_string(),
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "missing or unreadable public material {} for id={signing_key_id} in storage \"{}\": {e}",
            PubDataType::VerfAddress,
            public_storage.info()
        )
    })?;
    // Parsed rather than string-compared, and with `from_str` rather than
    // `parse_checksummed`, so an address written without EIP-55 casing still compares equal.
    let stored_address = alloy_primitives::Address::from_str(stored_address_text.trim())
        .map_err(|e| anyhow::anyhow!("{ERR_VERF_ADDRESS_MISMATCH}: {stored_address_text:?} in public storage is not a valid Ethereum address: {e}"))?;
    if stored_address != expected_address {
        anyhow::bail!(
            "{ERR_VERF_ADDRESS_MISMATCH}: public storage holds {stored_address}, expected {expected_address}"
        );
    }

    tracing::info!(
        "Verification key and address in public storage match the private signing key (address {})",
        expected_address
    );
    Ok(())
}

/// Public material that private storage does not account for, built by
/// [`report_unexpected_public_material`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UnexpectedPublicMaterial {
    /// Entries under a known data type whose ID nothing in private storage explains.
    unexpected_id: BTreeMap<PubDataType, BTreeSet<RequestId>>,
    /// Top-level names in public storage that are not a [`PubDataType`] folder: a folder with an
    /// unknown name, or an object at the root whatever its name.
    unknown_data_types: BTreeSet<String>,
    /// Data types whose folder could not be listed, with the listing error. A filename that is
    /// not a request ID lands here. The `None` key means the root listing itself failed.
    unlistable: BTreeMap<Option<PubDataType>, String>,
}

impl UnexpectedPublicMaterial {
    /// Returns the number of reported items across all three categories.
    pub(crate) fn unexpected_count(&self) -> usize {
        self.unexpected_id
            .values()
            .map(BTreeSet::len)
            .sum::<usize>()
            + self.unknown_data_types.len()
            + self.unlistable.len()
    }
}

/// Return, per public data type, every ID that private storage or a fixed convention accounts
/// for.
///
/// A keyset contributes its ID under each type its metadata lists. The deprecated
/// `PublicKeyMetadata` is accounted for under every keyset ID, because deployments upgraded from
/// before 0.14 still hold one per keyset. Signing material lives at fixed IDs. Decompression keys
/// have no private counterpart, so none is accounted for.
///
/// The match over [`PubDataType`] is exhaustive, so a new variant does not compile until it has
/// a rule here. Only data types with at least one accounted ID appear in the result.
fn expected_public_material(
    key_entries: &[(RequestId, KeyGenMetadata)],
    crs_entries: &HashMap<RequestId, CrsGenMetadata>,
    recovery_material: &HashMap<RequestId, RecoveryValidationMaterial>,
) -> BTreeMap<PubDataType, BTreeSet<RequestId>> {
    let mut expected = BTreeMap::new();
    for data_type in PubDataType::iter() {
        let ids: BTreeSet<RequestId> = match data_type {
            PubDataType::PublicKey | PubDataType::ServerKey | PubDataType::CompressedXofKeySet => {
                key_entries
                    .iter()
                    .filter(|(_, metadata)| match metadata {
                        KeyGenMetadata::Current(inner) => {
                            inner.key_digest_map.contains_key(&data_type)
                        }
                        KeyGenMetadata::LegacyV0(hash_map) => hash_map.contains_key(&data_type),
                    })
                    .map(|(key_id, _)| *key_id)
                    .collect()
            }
            // `PublicKeyMetadata` is deprecated because 0.14 and later do not write it. A
            // deployment upgraded from an earlier version still holds one entry per keyset, so
            // the sweep must account for it.
            #[expect(deprecated)]
            PubDataType::PublicKeyMetadata => {
                key_entries.iter().map(|(key_id, _)| *key_id).collect()
            }
            PubDataType::CRS => crs_entries.keys().copied().collect(),
            // The recovery material map is itself read by listing this folder, so this set always
            // matches what the folder holds. It is kept so that every data type has exactly one
            // rule.
            PubDataType::RecoveryMaterial => recovery_material.keys().copied().collect(),
            PubDataType::VerfKey | PubDataType::VerfAddress | PubDataType::CACert => {
                BTreeSet::from([*SIGNING_KEY_ID])
            }
            PubDataType::TypedVerfKey | PubDataType::TypedVerfAddress => {
                SigningSchemeType::iter().map(signing_material_id).collect()
            }
            PubDataType::DecompressionKey => BTreeSet::new(),
        };
        if !ids.is_empty() {
            expected.insert(data_type, ids);
        }
    }
    expected
}

/// Report public material that private storage does not account for.
///
/// Lists public storage and logs an error for every top-level name that is not a data type
/// folder, including every object directly under the root. It also logs an error for every entry
/// whose ID is not explained by private keyset or CRS metadata, by the node's signing material at
/// its fixed IDs, or by the recovery material already loaded from public storage.
/// Nothing here fails boot: some of it is legitimate (a retired keyset, a previous deployment
/// sharing the bucket) and the node cannot tell that apart from a corrupted or tampered store, so
/// the operator is told and left to decide. Read-only; never deserializes anything.
///
/// Bounded by the storage root the node is configured with (`PUB`, or `PUB-pX` for party X):
/// material under other parties' prefixes in a shared bucket is never listed. Sub-folders
/// beneath a data type are not descended into, since public data is never epoched.
pub(crate) async fn report_unexpected_public_material<S>(
    public_storage: &S,
    key_entries: &[(RequestId, KeyGenMetadata)],
    crs_entries: &HashMap<RequestId, CrsGenMetadata>,
    recovery_material: &HashMap<RequestId, RecoveryValidationMaterial>,
) -> UnexpectedPublicMaterial
where
    S: StorageReader + Sync,
{
    let expected = expected_public_material(key_entries, crs_entries, recovery_material);
    let mut report = UnexpectedPublicMaterial::default();
    let storage_info = public_storage.info();

    // Compared as exact strings: `PubDataType::from_str` is case-insensitive, but the storage
    // backends are not, so a folder that differs only in case holds no keyset.
    let known_data_types: BTreeSet<String> = PubDataType::iter().map(|t| t.to_string()).collect();
    match public_storage.all_data_types().await {
        Ok(entries) => {
            for name in entries.folders {
                if !known_data_types.contains(&name) {
                    tracing::error!(
                        "{ERR_UNKNOWN_PUBLIC_DATA_TYPE} \"{storage_info}\": \"{name}\" is not a known data type"
                    );
                    report.unknown_data_types.insert(name);
                }
            }
            // A data type stores its entries inside its folder only, so an object at the root is
            // a stray even when it carries a data type's name.
            for name in entries.objects {
                tracing::error!(
                    "{ERR_UNKNOWN_PUBLIC_DATA_TYPE} \"{storage_info}\": \"{name}\" is an object where only data type folders belong"
                );
                report.unknown_data_types.insert(name);
            }
        }
        Err(e) => {
            tracing::error!(
                "{ERR_UNLISTABLE_PUBLIC_MATERIAL} in storage \"{storage_info}\", so unknown data types were not detected: {e}"
            );
            report.unlistable.insert(None, e.to_string());
        }
    }

    for data_type in PubDataType::iter() {
        let found = match public_storage.all_data_ids(&data_type.to_string()).await {
            Ok(found) => found,
            Err(e) => {
                tracing::error!(
                    "{ERR_UNLISTABLE_PUBLIC_MATERIAL} {data_type} in storage \"{storage_info}\", so its entries were not reconciled: {e}"
                );
                report.unlistable.insert(Some(data_type), e.to_string());
                continue;
            }
        };
        let expected_ids = expected.get(&data_type);
        let unexpected: BTreeSet<RequestId> = found
            .into_iter()
            .filter(|id| !expected_ids.is_some_and(|ids| ids.contains(id)))
            .collect();
        for id in &unexpected {
            tracing::error!(
                "{ERR_UNEXPECTED_PUBLIC_MATERIAL} {data_type} for id={id} in storage \"{storage_info}\": private storage holds no counterpart"
            );
        }
        if !unexpected.is_empty() {
            report.unexpected_id.insert(data_type, unexpected);
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::custodian::InternalCustodianContext;
    use crate::backup::operator::RecoveryValidationMaterial;
    use crate::consts::DEFAULT_MPC_CONTEXT;
    use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::engine::base::KeyGenMetadataInner;
    use crate::engine::base::{DSEP_PUBDATA_CRS, ERR_INVALID_CURRENT_PUBLIC_KEY_SHAPE};
    use crate::engine::material_integrity::{
        ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH, ERR_CRS_DIGEST_MISMATCH,
        ERR_PUBLIC_KEY_DIGEST_MISMATCH, ERR_SERVER_KEY_DIGEST_MISMATCH,
    };
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::{Storage, delete_at_request_id, store_versioned_at_request_id};

    use aes_prng::AesRng;
    use hashing::{DomainSep, hash_element};
    use kms_grpc::rpc_types::SignedPubDataHandleInternal;
    use rand::SeedableRng;

    // Success cases deliberately use invalid encodings: if startup ever starts deserializing
    // key or CRS objects again, the ordinary matching-digest tests will fail.
    const RAW_PUBLIC_KEY: &[u8] = b"deliberately not a serialized TFHE public key";
    const RAW_SERVER_KEY: &[u8] = b"deliberately not a serialized TFHE server key";
    const RAW_COMPRESSED_KEYSET: &[u8] = b"deliberately not a serialized TFHE compressed keyset";
    const RAW_CRS: &[u8] = b"deliberately not a serialized TFHE CRS";

    #[derive(Clone)]
    struct TestStoredMaterial {
        key_id: RequestId,
        preproc_id: RequestId,
        key_digest_map: BTreeMap<PubDataType, Vec<u8>>,
    }

    impl TestStoredMaterial {
        fn current_metadata(&self) -> KeyGenMetadata {
            self.current_metadata_with_key_digests(self.key_digest_map.clone())
        }

        fn current_metadata_with_key_digests(
            &self,
            key_digest_map: BTreeMap<PubDataType, Vec<u8>>,
        ) -> KeyGenMetadata {
            KeyGenMetadata::Current(KeyGenMetadataInner {
                signatures: vec![],
                key_id: self.key_id,
                preprocessing_id: self.preproc_id,
                key_digest_map,
                eip712_domain: None,
                external_signature: vec![],
                extra_data: None,
            })
        }
    }

    #[tokio::test]
    async fn sanity_check_current_standard_keys_valid_digests() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 69).await;

        let entries = vec![(material.key_id, material.current_metadata())];
        verify_keysets(&storage, &entries)
            .await
            .expect("valid digests should pass");
    }

    #[tokio::test]
    async fn sanity_check_current_standard_keys_invalid_digest() {
        let mut storage = RamStorage::new();
        let mut material = setup_standard_keys(&mut storage, 70).await;
        if let Some(digest) = material.key_digest_map.get_mut(&PubDataType::ServerKey) {
            digest[0] ^= 0xFF;
        }

        let entries = vec![(material.key_id, material.current_metadata())];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string().contains(ERR_SERVER_KEY_DIGEST_MISMATCH),
            "expected server key digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_valid_digests() {
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 44).await;

        let entries = vec![(material.key_id, material.current_metadata())];
        verify_keysets(&storage, &entries)
            .await
            .expect("valid digests should pass");
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_invalid_public_key_digest() {
        let mut storage = RamStorage::new();
        let mut material = setup_compressed_keys(&mut storage, 45).await;
        if let Some(digest) = material.key_digest_map.get_mut(&PubDataType::PublicKey) {
            digest[0] ^= 0xFF;
        }

        let entries = vec![(material.key_id, material.current_metadata())];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string().contains(ERR_PUBLIC_KEY_DIGEST_MISMATCH),
            "expected public key digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_invalid_compressed_keyset_digest() {
        let mut storage = RamStorage::new();
        let mut material = setup_compressed_keys(&mut storage, 46).await;
        if let Some(digest) = material
            .key_digest_map
            .get_mut(&PubDataType::CompressedXofKeySet)
        {
            digest[0] ^= 0xFF;
        }

        let entries = vec![(material.key_id, material.current_metadata())];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH),
            "expected compressed keyset digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_missing_public_key_fails() {
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 47).await;
        delete_data(&mut storage, &material.key_id, PubDataType::PublicKey).await;

        let entries = vec![(material.key_id, material.current_metadata())];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(&PubDataType::PublicKey.to_string()),
            "expected missing public key error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keyset_without_public_key_fails_as_inconsistent() {
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 48).await;
        let mut key_digest_map = material.key_digest_map.clone();
        key_digest_map.remove(&PubDataType::PublicKey);
        let metadata = material.current_metadata_with_key_digests(key_digest_map);

        let entries = vec![(material.key_id, metadata)];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_CURRENT_PUBLIC_KEY_SHAPE),
            "expected invalid current shape error, got: {err}"
        );
    }

    #[tokio::test]
    async fn legacy_keyset_presence_check_does_not_deserialize_objects() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 49).await;

        let entries = vec![(
            material.key_id,
            legacy_keyset_metadata(&[PubDataType::PublicKey, PubDataType::ServerKey]),
        )];
        verify_keysets(&storage, &entries)
            .await
            .expect("legacy raw objects only need to be present");
    }

    #[tokio::test]
    async fn legacy_keysets_reject_invalid_metadata_shapes() {
        let storage = RamStorage::new();
        let key_id = RequestId::new_random(&mut AesRng::seed_from_u64(50));

        for data_types in [
            vec![PubDataType::PublicKey, PubDataType::CompressedXofKeySet],
            vec![PubDataType::PublicKey],
            vec![PubDataType::ServerKey],
        ] {
            let entries = vec![(key_id, legacy_keyset_metadata(&data_types))];
            let err = verify_keysets(&storage, &entries).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains(ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE),
                "expected invalid legacy shape error for {data_types:?}, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn sanity_check_crs_valid_digest() {
        let mut rng = AesRng::seed_from_u64(70);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let digest = setup_crs(&mut storage, &crs_id).await;
        let metadata = current_crs_metadata(crs_id, digest);

        let entries = HashMap::from_iter([(crs_id, metadata)]);
        verify_crses(&storage, &entries)
            .await
            .expect("valid CRS digest should pass");
    }

    #[tokio::test]
    async fn sanity_check_crs_invalid_digest() {
        let mut rng = AesRng::seed_from_u64(71);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let mut digest = setup_crs(&mut storage, &crs_id).await;
        digest[0] ^= 0xFF;
        let metadata = current_crs_metadata(crs_id, digest);

        let entries = HashMap::from_iter([(crs_id, metadata)]);
        let err = verify_crses(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string().contains(ERR_CRS_DIGEST_MISMATCH),
            "expected CRS digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn legacy_crs_presence_check_does_not_deserialize_object() {
        let mut rng = AesRng::seed_from_u64(72);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let _digest = setup_crs(&mut storage, &crs_id).await;

        let legacy_handle = SignedPubDataHandleInternal::new(String::new(), vec![], vec![]);
        let metadata = CrsGenMetadata::LegacyV0(legacy_handle);

        let entries = HashMap::from_iter([(crs_id, metadata)]);
        verify_crses(&storage, &entries)
            .await
            .expect("legacy raw CRS object only needs to be present");
    }

    // === Explicit presence errors ===

    #[tokio::test]
    async fn missing_server_key_error_names_the_type() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 100).await;
        delete_data(&mut storage, &material.key_id, PubDataType::ServerKey).await;

        let entries = vec![(material.key_id, material.current_metadata())];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing or unreadable public material")
                && msg.contains(&PubDataType::ServerKey.to_string())
                && msg.contains(&material.key_id.to_string()),
            "error should name the missing type and the key id, got: {msg}"
        );
    }

    #[tokio::test]
    async fn missing_crs_error_names_the_type() {
        let mut rng = AesRng::seed_from_u64(101);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        let digest = setup_crs(&mut storage, &crs_id).await;
        delete_data(&mut storage, &crs_id, PubDataType::CRS).await;

        let entries = HashMap::from([(crs_id, current_crs_metadata(crs_id, digest))]);
        let err = verify_crses(&storage, &entries).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing or unreadable public material")
                && msg.contains(&PubDataType::CRS.to_string())
                && msg.contains(&crs_id.to_string()),
            "error should name the missing type and the crs id, got: {msg}"
        );
    }

    #[tokio::test]
    async fn keygen_metadata_stored_under_a_different_id_is_rejected() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 116).await;
        let metadata = material.current_metadata();
        // A different seed than `setup_standard_keys` used, so this really is another ID.
        let other_id = RequestId::new_random(&mut AesRng::seed_from_u64(0xA116));
        assert_ne!(other_id, material.key_id);

        let err = ensure_keygen_metadata_id_matches(&other_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_ID_MISMATCH),
            "expected an ID mismatch, got: {err}"
        );
        ensure_keygen_metadata_id_matches(&material.key_id, &metadata)
            .expect("the ID it was stored under must be accepted");
    }

    #[tokio::test]
    async fn keygen_metadata_id_is_checked_before_public_storage_verification() {
        let mut storage = RamStorage::new();
        // Two keysets whose published bytes are identical, so their digests are too. Filing one
        // keyset's metadata under the other's ID therefore satisfies every digest check, and only
        // the declared-ID check can catch it.
        let material = setup_standard_keys(&mut storage, 117).await;
        let other = setup_standard_keys(&mut storage, 118).await;
        assert_ne!(other.key_id, material.key_id);
        assert_eq!(other.key_digest_map, material.key_digest_map);

        let metadata = material.current_metadata();
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(117));
        let entries = vec![(other.key_id, metadata)];

        // Nothing but the ID check stands between this and a clean boot: the digests match.
        verify_keysets(&storage, &entries)
            .await
            .expect("the digests match, so the digest checks alone cannot catch this");

        let err =
            verify_storage_material(&storage, &entries, &HashMap::new(), &HashMap::new(), &sk)
                .await
                .unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_ID_MISMATCH),
            "expected an ID mismatch before public storage verification, got: {err}"
        );
    }

    #[tokio::test]
    async fn crs_metadata_stored_under_a_different_id_is_rejected() {
        let mut rng = AesRng::seed_from_u64(123);
        let crs_id = RequestId::new_random(&mut rng);
        let other_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        let digest = setup_crs(&mut storage, &crs_id).await;
        let metadata = current_crs_metadata(crs_id, digest);

        let err = ensure_crs_metadata_id_matches(&other_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_ID_MISMATCH),
            "expected an ID mismatch, got: {err}"
        );
        ensure_crs_metadata_id_matches(&crs_id, &metadata)
            .expect("the ID it was stored under must be accepted");
    }

    #[tokio::test]
    async fn crs_metadata_id_is_checked_before_public_storage_verification() {
        let mut rng = AesRng::seed_from_u64(124);
        let crs_id = RequestId::new_random(&mut rng);
        let other_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        let digest = setup_crs(&mut storage, &crs_id).await;
        let metadata = current_crs_metadata(crs_id, digest);
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(124));

        let entries = HashMap::from([(other_id, metadata)]);
        let err = verify_storage_material(&storage, &[], &entries, &HashMap::new(), &sk)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_ID_MISMATCH),
            "expected an ID mismatch before public storage verification, got: {err}"
        );
    }

    // === Signing key material ===

    #[tokio::test]
    async fn signing_key_material_accepts_matching_key_and_address() {
        let mut storage = RamStorage::new();
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(130));
        store_signing_key_material(&mut storage, &sk, None).await;

        verify_signing_key_material(&storage, &sk)
            .await
            .expect("the derived key and address must match what was stored");
    }

    #[tokio::test]
    async fn signing_key_material_accepts_non_checksummed_address() {
        let mut storage = RamStorage::new();
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(131));
        let lowercased = PublicSigKey::from_sk(&sk)
            .address()
            .to_string()
            .to_lowercase();
        store_signing_key_material(&mut storage, &sk, Some(lowercased)).await;

        verify_signing_key_material(&storage, &sk)
            .await
            .expect("an address without EIP-55 casing must still compare equal");
    }

    #[tokio::test]
    async fn signing_key_material_rejects_wrong_verf_key() {
        let mut storage = RamStorage::new();
        let mut rng = AesRng::seed_from_u64(132);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let (_other_pk, other_sk) = gen_sig_keys(&mut rng);
        // Address matches, key does not — so this isolates the key comparison.
        let right_address = PublicSigKey::from_sk(&sk).address().to_string();
        store_signing_key_material(&mut storage, &other_sk, Some(right_address)).await;

        let err = verify_signing_key_material(&storage, &sk)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_VERF_KEY_MISMATCH),
            "expected a verification key mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn signing_key_material_rejects_wrong_verf_address() {
        let mut storage = RamStorage::new();
        let mut rng = AesRng::seed_from_u64(133);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let (other_pk, _other_sk) = gen_sig_keys(&mut rng);
        store_signing_key_material(&mut storage, &sk, Some(other_pk.address().to_string())).await;

        let err = verify_signing_key_material(&storage, &sk)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_VERF_ADDRESS_MISMATCH),
            "expected a verification address mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn signing_key_material_rejects_unparseable_verf_address() {
        let mut storage = RamStorage::new();
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(134));
        store_signing_key_material(&mut storage, &sk, Some("not-an-address".to_string())).await;

        let err = verify_signing_key_material(&storage, &sk)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_VERF_ADDRESS_MISMATCH),
            "expected a verification address mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn signing_key_material_rejects_missing_verf_key() {
        let storage = RamStorage::new();
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(135));

        let err = verify_signing_key_material(&storage, &sk)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing or unreadable public material")
                && msg.contains(&PubDataType::VerfKey.to_string()),
            "expected a missing VerfKey error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn signing_key_material_rejects_missing_verf_address() {
        let mut storage = RamStorage::new();
        let (pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(136));
        store_versioned_at_request_id(
            &mut storage,
            &SIGNING_KEY_ID,
            &pk,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();

        let err = verify_signing_key_material(&storage, &sk)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing or unreadable public material")
                && msg.contains(&PubDataType::VerfAddress.to_string()),
            "expected a missing VerfAddress error, got: {msg}"
        );
    }

    // === Extra material in public storage is reported but never fails boot ===

    #[tokio::test]
    async fn extra_verf_key_under_another_id_does_not_fail_but_is_reported() {
        let mut storage = RamStorage::new();
        let mut rng = AesRng::seed_from_u64(140);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        store_signing_key_material(&mut storage, &sk, None).await;

        // A leftover verification key under an unrelated ID. Reading by folder — as
        // `get_core_verification_key` does — would reject this as "not exactly one entry".
        let (other_pk, _other_sk) = gen_sig_keys(&mut rng);
        let other_id = RequestId::new_random(&mut rng);
        store_versioned_at_request_id(
            &mut storage,
            &other_id,
            &other_pk,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();

        verify_signing_key_material(&storage, &sk)
            .await
            .expect("an unrelated extra verification key must not fail the check");

        let report =
            report_unexpected_public_material(&storage, &[], &HashMap::new(), &HashMap::new())
                .await;
        assert_eq!(
            report.unexpected_id,
            BTreeMap::from([(PubDataType::VerfKey, BTreeSet::from([other_id]))])
        );
    }

    #[tokio::test]
    async fn unexpected_public_material_is_reported_and_boot_succeeds() {
        let mut storage = RamStorage::new();
        let mut rng = AesRng::seed_from_u64(141);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        store_signing_key_material(&mut storage, &sk, None).await;

        // Keysets and a CRS that private storage knows nothing about.
        let standard = setup_standard_keys(&mut storage, 142).await;
        let compressed = setup_compressed_keys(&mut storage, 143).await;
        let crs_id = RequestId::new_random(&mut rng);
        let _crs_digest = setup_crs(&mut storage, &crs_id).await;

        let report = verify_storage_material(&storage, &[], &HashMap::new(), &HashMap::new(), &sk)
            .await
            .expect("material with no private counterpart must not fail boot");
        let expected = BTreeMap::from([
            (
                PubDataType::PublicKey,
                BTreeSet::from([standard.key_id, compressed.key_id]),
            ),
            (PubDataType::ServerKey, BTreeSet::from([standard.key_id])),
            (
                PubDataType::CompressedXofKeySet,
                BTreeSet::from([compressed.key_id]),
            ),
            (PubDataType::CRS, BTreeSet::from([crs_id])),
        ]);
        assert_eq!(report.unexpected_id, expected);
        assert!(report.unknown_data_types.is_empty());
        assert!(report.unlistable.is_empty());
    }

    #[tokio::test]
    async fn unexpected_public_material_is_empty_for_consistent_storage() {
        let mut storage = RamStorage::new();
        let mut rng = AesRng::seed_from_u64(180);
        let standard = setup_standard_keys(&mut storage, 181).await;
        let compressed = setup_compressed_keys(&mut storage, 182).await;
        let crs_id = RequestId::new_random(&mut rng);
        let crs_digest = setup_crs(&mut storage, &crs_id).await;
        let (_pk, sk) = gen_sig_keys(&mut rng);
        store_signing_key_material(&mut storage, &sk, None).await;
        store_fixed_id_material(&mut storage).await;
        let recovery_material = test_recovery_material(&sk);
        let context_id = recovery_material.custodian_context().context_id;
        storage
            .store_bytes(
                b"recovery material",
                &context_id,
                &PubDataType::RecoveryMaterial.to_string(),
            )
            .await
            .unwrap();

        let entries = vec![
            (standard.key_id, standard.current_metadata()),
            (compressed.key_id, compressed.current_metadata()),
        ];
        let crs_entries = HashMap::from([(crs_id, current_crs_metadata(crs_id, crs_digest))]);
        let recovery = HashMap::from([(context_id, recovery_material)]);

        let report =
            report_unexpected_public_material(&storage, &entries, &crs_entries, &recovery).await;
        assert_eq!(
            report,
            UnexpectedPublicMaterial::default(),
            "consistent storage must report nothing"
        );
        assert_eq!(report.unexpected_count(), 0);
    }

    #[tokio::test]
    async fn stray_server_key_for_compressed_keyset_is_reported() {
        let mut storage = RamStorage::new();
        let compressed = setup_compressed_keys(&mut storage, 183).await;
        // A compressed keyset publishes no server key, so one under its own ID is a stray.
        store_raw_material(
            &mut storage,
            &compressed.key_id,
            PubDataType::ServerKey,
            RAW_SERVER_KEY,
            &DSEP_PUBDATA_KEY,
        )
        .await;

        let entries = vec![(compressed.key_id, compressed.current_metadata())];
        let report =
            report_unexpected_public_material(&storage, &entries, &HashMap::new(), &HashMap::new())
                .await;
        assert_eq!(
            report.unexpected_id,
            BTreeMap::from([(PubDataType::ServerKey, BTreeSet::from([compressed.key_id]))])
        );
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn public_key_metadata_is_reported_only_under_unknown_ids() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 184).await;
        let unknown_id = RequestId::new_random(&mut AesRng::seed_from_u64(185));
        let metadata_type = PubDataType::PublicKeyMetadata.to_string();
        // Deployments upgraded from before 0.14 keep one legacy metadata entry per keyset.
        storage
            .store_bytes(b"legacy metadata", &material.key_id, &metadata_type)
            .await
            .unwrap();
        storage
            .store_bytes(b"legacy metadata", &unknown_id, &metadata_type)
            .await
            .unwrap();

        let entries = vec![(material.key_id, material.current_metadata())];
        let report =
            report_unexpected_public_material(&storage, &entries, &HashMap::new(), &HashMap::new())
                .await;
        assert_eq!(
            report.unexpected_id,
            BTreeMap::from([(PubDataType::PublicKeyMetadata, BTreeSet::from([unknown_id]))])
        );
    }

    #[tokio::test]
    async fn decompression_key_entries_are_reported() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 186).await;
        // No private record accounts for a decompression key, not even under a known keyset ID.
        storage
            .store_bytes(
                b"decompression key",
                &material.key_id,
                &PubDataType::DecompressionKey.to_string(),
            )
            .await
            .unwrap();

        let entries = vec![(material.key_id, material.current_metadata())];
        let report =
            report_unexpected_public_material(&storage, &entries, &HashMap::new(), &HashMap::new())
                .await;
        assert_eq!(
            report.unexpected_id,
            BTreeMap::from([(
                PubDataType::DecompressionKey,
                BTreeSet::from([material.key_id])
            )])
        );
    }

    #[tokio::test]
    async fn duplicate_key_entries_across_epochs_report_nothing() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 187).await;
        // The threshold caller lists a reshared keyset once per epoch.
        let entries = vec![
            (material.key_id, material.current_metadata()),
            (material.key_id, material.current_metadata()),
        ];
        let report =
            report_unexpected_public_material(&storage, &entries, &HashMap::new(), &HashMap::new())
                .await;
        assert_eq!(report.unexpected_count(), 0, "got: {report:?}");
    }

    #[tokio::test]
    async fn unknown_data_type_folder_is_reported() {
        let mut storage = RamStorage::new();
        let id = RequestId::new_random(&mut AesRng::seed_from_u64(188));
        storage.store_bytes(b"?", &id, "Garbage").await.unwrap();
        // Case matters: the backends are case-sensitive, so this folder holds no keyset.
        storage.store_bytes(b"?", &id, "publickey").await.unwrap();

        let report =
            report_unexpected_public_material(&storage, &[], &HashMap::new(), &HashMap::new())
                .await;
        assert_eq!(
            report.unknown_data_types,
            BTreeSet::from(["Garbage".to_string(), "publickey".to_string()])
        );
        assert!(report.unexpected_id.is_empty());
        assert_eq!(report.unexpected_count(), 2);
    }

    #[tokio::test]
    async fn root_object_named_like_a_data_type_is_reported() {
        use crate::vault::storage::{StorageType, file::FileStorage};

        let temp_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(Some(temp_dir.path()), StorageType::PUB, None).unwrap();
        // No data type stores anything directly under the root, so the name does not excuse it.
        let name = PubDataType::PublicKey.to_string();
        std::fs::write(storage.root_dir().join(&name), b"x").unwrap();

        let report =
            report_unexpected_public_material(&storage, &[], &HashMap::new(), &HashMap::new())
                .await;
        assert_eq!(report.unknown_data_types, BTreeSet::from([name]));
        assert!(report.unexpected_id.is_empty());
    }

    #[tokio::test]
    async fn unlistable_folder_is_reported_and_boot_succeeds() {
        use crate::vault::storage::{StorageType, file::FileStorage};

        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PUB, None).unwrap();
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(192));
        store_signing_key_material(&mut storage, &sk, None).await;
        // A name that is not a request ID makes the folder listing fail.
        let public_key_dir = storage.root_dir().join(PubDataType::PublicKey.to_string());
        std::fs::create_dir_all(&public_key_dir).unwrap();
        std::fs::write(public_key_dir.join("not-a-request-id"), b"x").unwrap();

        let report = verify_storage_material(&storage, &[], &HashMap::new(), &HashMap::new(), &sk)
            .await
            .expect("an unlistable folder must not fail boot");
        assert!(
            report
                .unlistable
                .contains_key(&Some(PubDataType::PublicKey)),
            "got: {report:?}"
        );
        assert!(report.unexpected_id.is_empty());
    }

    #[test]
    fn expected_public_material_covers_fixed_id_signing_material() {
        let expected = expected_public_material(&[], &HashMap::new(), &HashMap::new());
        for data_type in [
            PubDataType::VerfKey,
            PubDataType::VerfAddress,
            PubDataType::CACert,
        ] {
            assert_eq!(
                expected.get(&data_type),
                Some(&BTreeSet::from([*SIGNING_KEY_ID])),
                "{data_type}"
            );
        }
        let typed: BTreeSet<RequestId> =
            SigningSchemeType::iter().map(signing_material_id).collect();
        for data_type in [PubDataType::TypedVerfKey, PubDataType::TypedVerfAddress] {
            assert_eq!(expected.get(&data_type), Some(&typed), "{data_type}");
        }
        // Nothing is accounted for without private records.
        for data_type in [
            PubDataType::PublicKey,
            PubDataType::ServerKey,
            PubDataType::CompressedXofKeySet,
            PubDataType::CRS,
            PubDataType::DecompressionKey,
            PubDataType::RecoveryMaterial,
        ] {
            assert!(!expected.contains_key(&data_type), "{data_type}");
        }
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn expected_public_material_follows_keyset_layout() {
        let mut storage = RamStorage::new();
        let standard = setup_standard_keys(&mut storage, 189).await;
        let compressed = setup_compressed_keys(&mut storage, 190).await;
        let legacy_id = RequestId::new_random(&mut AesRng::seed_from_u64(191));
        let entries = vec![
            (standard.key_id, standard.current_metadata()),
            (compressed.key_id, compressed.current_metadata()),
            (
                legacy_id,
                legacy_keyset_metadata(&[PubDataType::PublicKey, PubDataType::ServerKey]),
            ),
        ];

        let expected = expected_public_material(&entries, &HashMap::new(), &HashMap::new());
        let all_ids = BTreeSet::from([standard.key_id, compressed.key_id, legacy_id]);
        assert_eq!(expected[&PubDataType::PublicKey], all_ids);
        assert_eq!(
            expected[&PubDataType::ServerKey],
            BTreeSet::from([standard.key_id, legacy_id])
        );
        assert_eq!(
            expected[&PubDataType::CompressedXofKeySet],
            BTreeSet::from([compressed.key_id])
        );
        assert_eq!(expected[&PubDataType::PublicKeyMetadata], all_ids);
    }

    #[test]
    fn recovery_material_signature_verifies_with_private_signing_key() {
        let (_verf_key, signing_key) = gen_sig_keys(&mut AesRng::seed_from_u64(170));
        let material = test_recovery_material(&signing_key);
        let context_id = material.custodian_context().context_id;
        let materials = HashMap::from([(context_id, material)]);

        verify_recovery_material(&materials, &signing_key)
            .expect("recovery material signed by the node must verify");
    }

    #[test]
    fn recovery_material_signature_rejects_wrong_private_signing_key() {
        let (_verf_key, signing_key) = gen_sig_keys(&mut AesRng::seed_from_u64(171));
        let (_wrong_verf_key, wrong_signing_key) = gen_sig_keys(&mut AesRng::seed_from_u64(172));
        let material = test_recovery_material(&signing_key);
        let context_id = material.custodian_context().context_id;
        let materials = HashMap::from([(context_id, material)]);

        let err = verify_recovery_material(&materials, &wrong_signing_key)
            .expect_err("recovery material signed by another node must be rejected");
        assert!(
            err.to_string()
                .contains("Invalid recovery validation material"),
            "expected an invalid recovery material error, got: {err}"
        );
    }

    #[test]
    fn private_standard_keygen_metadata_signature_verifies_with_stored_domain() {
        let mut rng = AesRng::seed_from_u64(176);
        let (_verf_key, signing_key) = gen_sig_keys(&mut rng);
        let domain = crate::dummy_domain();
        let prep_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let metadata = crate::engine::base::compute_info_standard_keygen_from_digests(
            &signing_key,
            &[],
            &prep_id,
            &key_id,
            vec![0x11; 32],
            vec![0x22; 32],
            &domain,
            vec![0x03],
        )
        .expect("standard keygen metadata construction must succeed");

        let KeyGenMetadata::Current(inner) = &metadata else {
            panic!("metadata construction must produce current metadata");
        };
        verify_keygen_metadata_signature(
            &key_id,
            inner,
            PublicSigKey::from_sk(&signing_key).address(),
        )
        .expect("the stored domain must verify the standard keygen signature");

        // The server-key digest is the field that separates the standard signed message from
        // the compressed one, so changing it must invalidate the signature.
        let mut tampered_inner = inner.clone();
        tampered_inner
            .key_digest_map
            .insert(PubDataType::ServerKey, vec![0x44; 32]);
        let err = verify_keygen_metadata_signature(
            &key_id,
            &tampered_inner,
            PublicSigKey::from_sk(&signing_key).address(),
        )
        .expect_err("a changed server-key digest must invalidate the signature");
        assert!(
            err.to_string().contains("Invalid EIP-712 signature"),
            "expected a signature verification error, got: {err}"
        );
    }

    #[test]
    fn private_compressed_keygen_metadata_signature_verifies_with_stored_domain() {
        let mut rng = AesRng::seed_from_u64(174);
        let (_verf_key, signing_key) = gen_sig_keys(&mut rng);
        let domain = crate::dummy_domain();
        let prep_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let metadata = crate::engine::base::compute_info_compressed_keygen_from_digests(
            &signing_key,
            &[],
            &prep_id,
            &key_id,
            vec![0x11; 32],
            vec![0x22; 32],
            &domain,
            vec![0x03],
        )
        .expect("compressed keygen metadata construction must succeed");

        let KeyGenMetadata::Current(inner) = &metadata else {
            panic!("metadata construction must produce current metadata");
        };
        verify_keygen_metadata_signature(
            &key_id,
            inner,
            PublicSigKey::from_sk(&signing_key).address(),
        )
        .expect("the stored domain must verify the compressed keygen signature");

        let wrong_domain = alloy_sol_types::eip712_domain!(
            name: "wrong domain",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let mut tampered_inner = inner.clone();
        tampered_inner.eip712_domain = Some((&wrong_domain).into());
        let err = verify_keygen_metadata_signature(
            &key_id,
            &tampered_inner,
            PublicSigKey::from_sk(&signing_key).address(),
        )
        .expect_err("a changed stored domain must invalidate the signature");
        assert!(
            err.to_string().contains("Invalid EIP-712 signature"),
            "expected a signature verification error, got: {err}"
        );
    }

    #[test]
    fn private_crs_metadata_signature_verifies_with_stored_domain() {
        let mut rng = AesRng::seed_from_u64(175);
        let (_verf_key, signing_key) = gen_sig_keys(&mut rng);
        let crs_id = RequestId::new_random(&mut rng);
        let metadata = crate::engine::base::compute_info_crs_from_digest(
            &signing_key,
            &[],
            &crs_id,
            vec![0x33; 32],
            64,
            &crate::dummy_domain(),
            vec![0x04],
        )
        .expect("CRS metadata construction must succeed");

        let CrsGenMetadata::Current(inner) = &metadata else {
            panic!("metadata construction must produce current metadata");
        };
        verify_crs_metadata_signature(
            &crs_id,
            inner,
            PublicSigKey::from_sk(&signing_key).address(),
        )
        .expect("the stored domain must verify the CRS signature");
    }

    // === End to end ===

    #[tokio::test]
    async fn verify_storage_material_accepts_consistent_storage() {
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(161));
        let (storage, entries, crs_entries) = setup_consistent_material(160, &sk, &sk).await;

        verify_storage_material(
            &storage,
            &entries,
            &crs_entries,
            &recovery_material_for(&sk),
            &sk,
        )
        .await
        .expect("consistent public storage must verify");
    }

    #[tokio::test]
    async fn verify_storage_material_rejects_metadata_signed_by_another_key() {
        let mut rng = AesRng::seed_from_u64(162);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let (other_pk, other_sk) = gen_sig_keys(&mut rng);
        // Everything public storage holds is this node's own and internally consistent; only
        // the private metadata was signed by another node's key. Material replicated from a
        // peer and then filed as ours would look exactly like this.
        let (storage, entries, _crs_entries) = setup_consistent_material(163, &other_sk, &sk).await;

        let err = verify_storage_material(
            &storage,
            &entries,
            &HashMap::new(),
            &recovery_material_for(&sk),
            &sk,
        )
        .await
        .expect_err("metadata signed by another key must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Invalid EIP-712 signature")
                && msg.contains(&other_pk.address().to_string())
                && msg.contains(&PublicSigKey::from_sk(&sk).address().to_string()),
            "error should name both the recovered and the expected signer, got: {msg}"
        );
    }

    #[tokio::test]
    async fn verify_storage_material_accepts_current_metadata_without_stored_domain() {
        let mut rng = AesRng::seed_from_u64(164);
        let mut storage = RamStorage::new();
        let (_pk, sk) = gen_sig_keys(&mut rng);
        store_signing_key_material(&mut storage, &sk, None).await;

        // Metadata written before the EIP-712 domain was persisted: current format, but with
        // no domain and therefore no signature that can be rebuilt. Every already-deployed
        // node holds only entries of this shape, so startup must keep accepting them.
        let material = setup_standard_keys(&mut storage, 165).await;
        let metadata = material.current_metadata();
        assert!(
            matches!(&metadata, KeyGenMetadata::Current(inner) if inner.eip712_domain.is_none()),
            "this test is only meaningful for current metadata with no stored domain"
        );
        let entries = vec![(material.key_id, metadata)];

        let crs_id = RequestId::new_random(&mut rng);
        let crs_digest = setup_crs(&mut storage, &crs_id).await;
        let crs_metadata = current_crs_metadata(crs_id, crs_digest);
        assert!(
            matches!(&crs_metadata, CrsGenMetadata::Current(inner) if inner.eip712_domain.is_none()),
            "this test is only meaningful for current CRS metadata with no stored domain"
        );
        let crs_entries = HashMap::from_iter([(crs_id, crs_metadata)]);

        verify_storage_material(
            &storage,
            &entries,
            &crs_entries,
            &recovery_material_for(&sk),
            &sk,
        )
        .await
        .expect("current metadata without a stored domain must still verify");
    }

    // === Helpers ===

    /// Public storage that is consistent by construction — matching key and CRS digests plus a
    /// published verification key and address — together with the private metadata describing
    /// it.
    ///
    /// `metadata_sk` signs the metadata and `node_sk` is the key the node boots with. Passing
    /// two different keys yields storage whose only defect is the metadata signature.
    async fn setup_consistent_material(
        seed: u64,
        metadata_sk: &PrivateSigKey,
        node_sk: &PrivateSigKey,
    ) -> (
        RamStorage,
        Vec<(RequestId, KeyGenMetadata)>,
        HashMap<RequestId, CrsGenMetadata>,
    ) {
        let mut rng = AesRng::seed_from_u64(seed);
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, seed + 1).await;
        store_signing_key_material(&mut storage, node_sk, None).await;
        let domain = crate::dummy_domain();

        let key_metadata = crate::engine::base::compute_info_standard_keygen_from_digests(
            metadata_sk,
            &[],
            &material.preproc_id,
            &material.key_id,
            material
                .key_digest_map
                .get(&PubDataType::ServerKey)
                .cloned()
                .expect("test material must contain a server-key digest"),
            material
                .key_digest_map
                .get(&PubDataType::PublicKey)
                .cloned()
                .expect("test material must contain a public-key digest"),
            &domain,
            vec![],
        )
        .expect("signed keygen metadata construction must succeed");

        let crs_id = RequestId::new_random(&mut rng);
        let crs_digest = setup_crs(&mut storage, &crs_id).await;
        let crs_metadata = crate::engine::base::compute_info_crs_from_digest(
            metadata_sk,
            &[],
            &crs_id,
            crs_digest,
            64,
            &domain,
            vec![],
        )
        .expect("signed CRS metadata construction must succeed");

        (
            storage,
            vec![(material.key_id, key_metadata)],
            HashMap::from_iter([(crs_id, crs_metadata)]),
        )
    }

    /// Recovery validation material signed by `signing_key`, keyed by its own context ID, so
    /// end-to-end tests can pass the recovery check and isolate what they are actually testing.
    fn recovery_material_for(
        signing_key: &PrivateSigKey,
    ) -> HashMap<RequestId, RecoveryValidationMaterial> {
        let material = test_recovery_material(signing_key);
        let context_id = material.custodian_context().context_id;
        HashMap::from([(context_id, material)])
    }

    fn test_recovery_material(signing_key: &PrivateSigKey) -> RecoveryValidationMaterial {
        let mut rng = AesRng::seed_from_u64(173);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_decryption_key, backup_enc_key) = encryption
            .keygen()
            .expect("test encryption key generation must succeed");
        let context = InternalCustodianContext {
            threshold: 0,
            context_id: RequestId::new_random(&mut rng),
            custodian_nodes: BTreeMap::new(),
            backup_enc_key,
        };

        RecoveryValidationMaterial::new(
            BTreeMap::new(),
            BTreeMap::new(),
            context,
            signing_key,
            *DEFAULT_MPC_CONTEXT,
        )
        .expect("test recovery material construction must succeed")
    }

    /// Store `CACert` and every scheme's typed verification material at their fixed IDs, so
    /// the expected sets for those types are fully populated.
    async fn store_fixed_id_material(storage: &mut RamStorage) {
        storage
            .store_bytes(
                b"ca cert",
                &SIGNING_KEY_ID,
                &PubDataType::CACert.to_string(),
            )
            .await
            .unwrap();
        for scheme in SigningSchemeType::iter() {
            let id = signing_material_id(scheme);
            for data_type in [PubDataType::TypedVerfKey, PubDataType::TypedVerfAddress] {
                storage
                    .store_bytes(b"typed material", &id, &data_type.to_string())
                    .await
                    .unwrap();
            }
        }
    }

    /// Write the `VerfKey` and `VerfAddress` a node publishes for its signing key.
    /// `address_override` lets a test store an address that does not match `sk`.
    async fn store_signing_key_material<S: Storage>(
        storage: &mut S,
        sk: &PrivateSigKey,
        address_override: Option<String>,
    ) {
        let pk = PublicSigKey::from_sk(sk);
        store_versioned_at_request_id(
            storage,
            &SIGNING_KEY_ID,
            &pk,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();
        let address = address_override.unwrap_or_else(|| pk.address().to_string());
        crate::vault::storage::store_text_at_request_id(
            storage,
            &SIGNING_KEY_ID,
            &address,
            &PubDataType::VerfAddress.to_string(),
        )
        .await
        .unwrap();
    }

    fn legacy_keyset_metadata(data_types: &[PubDataType]) -> KeyGenMetadata {
        KeyGenMetadata::LegacyV0(
            data_types
                .iter()
                .map(|data_type| {
                    (
                        *data_type,
                        SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
                    )
                })
                .collect(),
        )
    }

    fn current_crs_metadata(crs_id: RequestId, crs_digest: Vec<u8>) -> CrsGenMetadata {
        CrsGenMetadata::Current(crate::engine::base::CrsGenMetadataInner {
            crs_id,
            crs_digest,
            max_num_bits: 64,
            extra_data: None,
            eip712_domain: None,
            external_signature: vec![],
            signatures: vec![],
        })
    }

    async fn store_raw_material(
        storage: &mut RamStorage,
        id: &RequestId,
        data_type: PubDataType,
        bytes: &[u8],
        domain_separator: &DomainSep,
    ) -> Vec<u8> {
        storage
            .store_bytes(bytes, id, &data_type.to_string())
            .await
            .unwrap();
        hash_element(domain_separator, bytes)
    }

    async fn setup_keyset(
        storage: &mut RamStorage,
        seed: u64,
        additional_data_type: PubDataType,
        additional_bytes: &[u8],
    ) -> TestStoredMaterial {
        let mut rng = AesRng::seed_from_u64(seed);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let public_key_digest = store_raw_material(
            storage,
            &key_id,
            PubDataType::PublicKey,
            RAW_PUBLIC_KEY,
            &DSEP_PUBDATA_KEY,
        )
        .await;
        let additional_digest = store_raw_material(
            storage,
            &key_id,
            additional_data_type,
            additional_bytes,
            &DSEP_PUBDATA_KEY,
        )
        .await;

        TestStoredMaterial {
            key_id,
            preproc_id,
            key_digest_map: BTreeMap::from_iter([
                (additional_data_type, additional_digest),
                (PubDataType::PublicKey, public_key_digest),
            ]),
        }
    }

    async fn setup_standard_keys(storage: &mut RamStorage, seed: u64) -> TestStoredMaterial {
        setup_keyset(storage, seed, PubDataType::ServerKey, RAW_SERVER_KEY).await
    }

    async fn setup_compressed_keys(storage: &mut RamStorage, seed: u64) -> TestStoredMaterial {
        setup_keyset(
            storage,
            seed,
            PubDataType::CompressedXofKeySet,
            RAW_COMPRESSED_KEYSET,
        )
        .await
    }

    async fn delete_data(storage: &mut RamStorage, key_id: &RequestId, data_type: PubDataType) {
        delete_at_request_id(storage, key_id, &data_type.to_string())
            .await
            .unwrap();
    }

    async fn setup_crs(storage: &mut RamStorage, crs_id: &RequestId) -> Vec<u8> {
        store_raw_material(
            storage,
            crs_id,
            PubDataType::CRS,
            RAW_CRS,
            &DSEP_PUBDATA_CRS,
        )
        .await
    }
}
