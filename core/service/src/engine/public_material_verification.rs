//! Verification of the material published in public storage.
//!
//! Public storage may deviate from a consistent state: a misconfigured bucket or prefix can
//! point a node at the wrong material, and writes are not atomic, so a crash part-way through
//! an operation can leave an entry missing, truncated, or stale. Private storage holds the
//! digests and signatures that say what the published material should be, so it is the
//! reference, and every check here runs in that direction — an expected value is taken from
//! private storage and compared against what public storage holds, never the other way around.
//!
//! Three rules govern everything here:
//!
//! 1. **Private storage is the reference.** Iteration is always "for each entry in private
//!    storage, look up its counterpart in public storage".
//! 2. **Extra material in public storage is legitimate and silently ignored.** Most of it is
//!    there on purpose: a node may periodically replicate other parties' public material into
//!    its own public storage, so entries this node never generated — and holds no private
//!    counterpart for — are expected. Retired keysets and leftovers from a previous deployment
//!    sharing the bucket land there too. Verification therefore never asks "is there anything
//!    here I do not recognise", and orphans produce neither errors nor warnings.
//! 3. **Read-only.** Nothing here writes to, repairs, or re-fetches public storage.
//!
//! Startup verification operates on raw stored bytes. It never deserializes stored keys or
//! CRSes: current material is checked by hashing those bytes, while legacy material (which has
//! no digest) is checked for presence only.

use crate::consts::SIGNING_KEY_ID;
use crate::cryptography::signing::ecdsa::{PrivateSigKey, PublicSigKey};
use crate::cryptography::signing::{Signature, SigningSchemeType, unified_verify};
use crate::engine::base::{
    CrsGenMetadata, DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY, KeyGenMetadata, StoredTypedSignature,
    crs_payload_bytes, keygen_payload_bytes,
};
use crate::engine::material_integrity::{
    verify_compressed_key_digest_from_bytes, verify_crs_digest_from_bytes,
    verify_public_key_digest_from_bytes, verify_server_key_digest_from_bytes,
};
use crate::vault::storage::{StorageReader, read_text_at_request_id};
use hashing::DomainSep;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::PubDataType;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

const ERR_INVALID_CURRENT_PUBLIC_KEY_SHAPE: &str = "Invalid current public key metadata shape";
const ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE: &str = "Invalid legacy public key metadata shape";
pub(crate) const ERR_METADATA_SIGNATURE_INVALID: &str = "Result metadata signature invalid";
pub(crate) const ERR_METADATA_ID_MISMATCH: &str =
    "Result metadata is stored under a different ID than it declares";
pub(crate) const ERR_VERF_KEY_MISMATCH: &str =
    "Verification key in public storage does not match the private signing key";
pub(crate) const ERR_VERF_ADDRESS_MISMATCH: &str =
    "Verification address in public storage does not match the private signing key";

#[derive(Clone, Copy)]
enum CurrentPublicMaterialLayout {
    Standard,
    Compressed,
}

fn classify_current_public_material(
    key_digest_map: &BTreeMap<PubDataType, Vec<u8>>,
) -> anyhow::Result<CurrentPublicMaterialLayout> {
    let has_public_key = key_digest_map.contains_key(&PubDataType::PublicKey);
    let has_server_key = key_digest_map.contains_key(&PubDataType::ServerKey);
    let has_compressed_keyset = key_digest_map.contains_key(&PubDataType::CompressedXofKeySet);

    match (
        has_public_key,
        has_server_key,
        has_compressed_keyset,
        key_digest_map.len(),
    ) {
        (true, true, false, 2) => Ok(CurrentPublicMaterialLayout::Standard),
        (true, false, true, 2) => Ok(CurrentPublicMaterialLayout::Compressed),
        _ => anyhow::bail!(
            "{ERR_INVALID_CURRENT_PUBLIC_KEY_SHAPE}: expected either \
             {{PublicKey, ServerKey}} or {{PublicKey, CompressedXofKeySet}}, got {:?}",
            key_digest_map.keys().collect::<Vec<_>>()
        ),
    }
}

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
async fn verify_digests<S: StorageReader + Sync>(
    storage: &S,
    id: &RequestId,
    key_digest_map: &BTreeMap<PubDataType, Vec<u8>>,
) -> anyhow::Result<()> {
    let layout = classify_current_public_material(key_digest_map)?;
    let expected_public_key_digest = key_digest_map
        .get(&PubDataType::PublicKey)
        .ok_or_else(|| anyhow::anyhow!("missing digest for public key, id={id}"))?;
    {
        let public_key_bytes = load_public_bytes(storage, id, PubDataType::PublicKey).await?;
        verify_public_key_digest_from_bytes(&public_key_bytes, expected_public_key_digest)?;
    }

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
                verify_digests(public_storage, id, &inner.key_digest_map).await?;
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

/// Verify the per-scheme signatures a result was persisted with, against this node's own
/// verification keys, and return how many were skipped.
///
/// `Ecdsa256k1` entries are skipped and counted. They sign an EIP-712 hash, and the
/// `Eip712Domain` that hash is built from (chain ID plus verifying contract) arrives on the
/// originating gRPC request and is never persisted, so the message cannot be reconstructed
/// here. Every other scheme signs `payload_bytes` directly and is fully checkable.
///
/// Private storage remains the reference — its digests define what is expected. This check
/// covers the reference itself: a truncated write, a partially applied migration, or bit-rot
/// in the metadata blob would otherwise turn a damaged digest into a false accusation against
/// intact published material.
fn verify_stored_signatures(
    sk: &PrivateSigKey,
    dsep: &DomainSep,
    payload_bytes: &[u8],
    signatures: &[StoredTypedSignature],
    subject: &str,
) -> anyhow::Result<usize> {
    let mut skipped = 0;
    for stored in signatures {
        if stored.scheme == SigningSchemeType::Ecdsa256k1 {
            skipped += 1;
            continue;
        }
        let verification_key = sk.unified_verifying_key(stored.scheme).map_err(|e| {
            anyhow::anyhow!(
                "cannot derive the {} verification key needed to check {subject}: {e}",
                stored.scheme
            )
        })?;
        let signature = Signature::new(stored.scheme, stored.signature.clone());
        unified_verify(dsep, payload_bytes, &signature, &verification_key).map_err(|e| {
            anyhow::anyhow!(
                "{ERR_METADATA_SIGNATURE_INVALID}: {} signature over {subject} did not verify: {e}",
                stored.scheme
            )
        })?;
    }
    Ok(skipped)
}

/// Verify the signatures persisted alongside a keygen result's digests.
///
/// Returns the number of signatures skipped because they are ECDSA/EIP-712; see
/// [`verify_stored_signatures`]. `LegacyV0` metadata carries no per-scheme signatures, so
/// there is nothing to check for it.
fn verify_keygen_metadata_signatures(
    sk: &PrivateSigKey,
    key_id: &RequestId,
    metadata: &KeyGenMetadata,
) -> anyhow::Result<usize> {
    let KeyGenMetadata::Current(inner) = metadata else {
        return Ok(0);
    };
    // The published bytes are loaded under the storage ID, while the signature covers
    // `inner.key_id`. If those disagree, the two checks are talking about different keys and
    // neither result means anything.
    if inner.key_id != *key_id {
        anyhow::bail!(
            "{ERR_METADATA_ID_MISMATCH}: keygen metadata stored under key_id={key_id} declares \
             key_id={}",
            inner.key_id
        );
    }
    if inner.signatures.is_empty() {
        return Ok(0);
    }
    let payload_bytes = keygen_payload_bytes(
        &inner.preprocessing_id,
        &inner.key_id,
        &inner.key_digest_map,
        // `extra_data` is stored as `None` when it was empty at signing time, so map it back.
        inner.extra_data.as_deref().unwrap_or_default(),
    )?;
    verify_stored_signatures(
        sk,
        &DSEP_PUBDATA_KEY,
        &payload_bytes,
        &inner.signatures,
        &format!("keygen metadata for key_id={key_id}"),
    )
}

/// Verify the signatures persisted alongside a CRS result's digest.
///
/// Returns the number of signatures skipped because they are ECDSA/EIP-712; see
/// [`verify_stored_signatures`].
fn verify_crs_metadata_signatures(
    sk: &PrivateSigKey,
    crs_id: &RequestId,
    metadata: &CrsGenMetadata,
) -> anyhow::Result<usize> {
    let CrsGenMetadata::Current(inner) = metadata else {
        return Ok(0);
    };
    // See the equivalent check in `verify_keygen_metadata_signatures`.
    if inner.crs_id != *crs_id {
        anyhow::bail!(
            "{ERR_METADATA_ID_MISMATCH}: CRS metadata stored under crs_id={crs_id} declares \
             crs_id={}",
            inner.crs_id
        );
    }
    if inner.signatures.is_empty() {
        return Ok(0);
    }
    let payload_bytes = crs_payload_bytes(
        &inner.crs_id,
        inner.max_num_bits,
        &inner.crs_digest,
        inner.extra_data.as_deref().unwrap_or_default(),
    )?;
    verify_stored_signatures(
        sk,
        &DSEP_PUBDATA_CRS,
        &payload_bytes,
        &inner.signatures,
        &format!("CRS metadata for crs_id={crs_id}"),
    )
}

/// Check that the verification key and Ethereum address published in public storage are the
/// ones derived from the private signing key.
///
/// Both entries are read at [`SIGNING_KEY_ID`] specifically rather than by enumerating the
/// folder, so an unrelated leftover entry under a different ID is ignored. In particular this
/// must not go through `get_core_verification_key`, which fails unless public storage holds
/// exactly one verification key.
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

/// Verify everything private storage says public storage should contain.
///
/// Runs once during service construction, before the node serves. Fails the boot when
/// published material is missing, when its digest does not match the private reference, when
/// a persisted signature does not verify, or when the published verification key disagrees
/// with the private signing key. Extra material in public storage is ignored.
///
/// Pass `signing_key` as `None` only when the node has no private signing key, i.e. when
/// [`crate::engine::base::BaseKmsStruct::sig_key`] returns an error because the struct was
/// built by `new_no_signing_key`. `kms-server` does that when the private signing key cannot
/// be read, logging "ENTERING RECOVERY MODE"; there is no separate flag for that state. The
/// node's verification key then came out of public storage itself, so checking it back against
/// public storage would be circular — the signature and signing-key checks are skipped with a
/// warning, while the digest checks still run.
pub async fn verify_public_material<S>(
    public_storage: &S,
    key_entries: &[(RequestId, KeyGenMetadata)],
    crs_entries: &HashMap<RequestId, CrsGenMetadata>,
    signing_key: Option<&PrivateSigKey>,
) -> anyhow::Result<()>
where
    S: StorageReader + Sync,
{
    verify_keysets(public_storage, key_entries).await?;
    verify_crses(public_storage, crs_entries).await?;

    match signing_key {
        Some(sk) => {
            let mut skipped = 0;
            for (key_id, metadata) in key_entries {
                skipped += verify_keygen_metadata_signatures(sk, key_id, metadata)?;
            }
            for (crs_id, metadata) in crs_entries {
                skipped += verify_crs_metadata_signatures(sk, crs_id, metadata)?;
            }
            if skipped > 0 {
                tracing::info!(
                    "Skipped {skipped} ECDSA/EIP-712 signature(s) while verifying public material: \
                     the EIP-712 domain they were signed under is not persisted, so the signed \
                     message cannot be reconstructed at boot."
                );
            }
            verify_signing_key_material(public_storage, sk).await?;
        }
        None => tracing::warn!(
            "No signing key available (recovery mode): skipping signature verification of result \
             metadata and the verification-key check against public storage. Digest verification \
             of the published material still ran."
        ),
    }

    tracing::info!(
        "Verified public material in storage \"{}\": {} keyset(s), {} CRS(es)",
        public_storage.info(),
        key_entries.len(),
        crs_entries.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::engine::base::KeyGenMetadataInner;
    use crate::engine::centralized::central_kms::gen_centralized_crs;
    use crate::engine::material_integrity::{
        ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH, ERR_CRS_DIGEST_MISMATCH,
        ERR_PUBLIC_KEY_DIGEST_MISMATCH, ERR_SERVER_KEY_DIGEST_MISMATCH,
    };
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::{Storage, delete_at_request_id, store_versioned_at_request_id};

    use aes_prng::AesRng;
    use hashing::{hash_element, hash_versioned};
    use kms_grpc::rpc_types::SignedPubDataHandleInternal;
    use rand::SeedableRng;
    use tfhe::core_crypto::prelude::NormalizedHammingWeightBound;
    use tfhe::shortint::ClassicPBSParameters;
    use tfhe::xof_key_set::CompressedXofKeySet;

    #[derive(Clone)]
    struct TestStoredMaterial {
        key_id: RequestId,
        preproc_id: RequestId,
        key_digest_map: BTreeMap<PubDataType, Vec<u8>>,
    }

    impl TestStoredMaterial {
        fn current_metadata(&self) -> KeyGenMetadata {
            KeyGenMetadata::Current(KeyGenMetadataInner {
                signatures: vec![],
                key_id: self.key_id,
                preprocessing_id: self.preproc_id,
                key_digest_map: self.key_digest_map.clone(),
                external_signature: vec![],
                extra_data: None,
            })
        }

        fn legacy_standard_metadata(&self) -> KeyGenMetadata {
            KeyGenMetadata::LegacyV0(HashMap::from_iter([
                (
                    PubDataType::PublicKey,
                    SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
                ),
                (
                    PubDataType::ServerKey,
                    SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
                ),
            ]))
        }

        /// Metadata produced the way `key_gen` produces it, so the per-scheme signatures
        /// cover exactly the bytes production signs. Returns the signing key alongside it.
        fn signed_metadata(
            &self,
            schemes: &[SigningSchemeType],
        ) -> (KeyGenMetadata, PrivateSigKey) {
            let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(0x516E));
            let metadata = crate::engine::base::compute_info_standard_keygen_from_digests(
                &sk,
                schemes,
                &self.preproc_id,
                &self.key_id,
                self.key_digest_map
                    .get(&PubDataType::ServerKey)
                    .expect("standard material always has a server key digest")
                    .clone(),
                self.key_digest_map
                    .get(&PubDataType::PublicKey)
                    .expect("standard material always has a public key digest")
                    .clone(),
                &crate::dummy_domain(),
                vec![],
            )
            .unwrap();
            (metadata, sk)
        }

        fn current_metadata_with_types(&self, pub_data_types: &[PubDataType]) -> KeyGenMetadata {
            let key_digest_map = pub_data_types
                .iter()
                .filter_map(|data_type| {
                    self.key_digest_map
                        .get(data_type)
                        .cloned()
                        .map(|digest| (*data_type, digest))
                })
                .collect();
            KeyGenMetadata::Current(KeyGenMetadataInner {
                signatures: vec![],
                key_id: self.key_id,
                preprocessing_id: self.preproc_id,
                key_digest_map,
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
    async fn current_hash_checks_do_not_deserialize_keys_or_crs() {
        let mut rng = AesRng::seed_from_u64(0xA11CE);
        let key_id = RequestId::new_random(&mut rng);
        let preprocessing_id = RequestId::new_random(&mut rng);
        let crs_id = RequestId::new_random(&mut rng);
        let public_key_bytes = b"not a serialized TFHE public key";
        let server_key_bytes = b"not a serialized TFHE server key";
        let crs_bytes = b"not a serialized TFHE CRS";
        let mut storage = RamStorage::new();

        for (data_type, bytes) in [
            (PubDataType::PublicKey, public_key_bytes.as_slice()),
            (PubDataType::ServerKey, server_key_bytes.as_slice()),
        ] {
            storage
                .store_bytes(bytes, &key_id, &data_type.to_string())
                .await
                .unwrap();
        }
        storage
            .store_bytes(crs_bytes, &crs_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        let key_entries = vec![(
            key_id,
            KeyGenMetadata::Current(KeyGenMetadataInner {
                signatures: vec![],
                key_id,
                preprocessing_id,
                key_digest_map: BTreeMap::from([
                    (
                        PubDataType::PublicKey,
                        hash_element(&DSEP_PUBDATA_KEY, public_key_bytes),
                    ),
                    (
                        PubDataType::ServerKey,
                        hash_element(&DSEP_PUBDATA_KEY, server_key_bytes),
                    ),
                ]),
                external_signature: vec![],
                extra_data: None,
            }),
        )];
        let crs_entries = HashMap::from([(
            crs_id,
            CrsGenMetadata::Current(crate::engine::base::CrsGenMetadataInner {
                crs_id,
                crs_digest: hash_element(&DSEP_PUBDATA_CRS, crs_bytes),
                max_num_bits: 64,
                extra_data: None,
                external_signature: vec![],
                signatures: vec![],
            }),
        )]);

        verify_keysets(&storage, &key_entries)
            .await
            .expect("matching raw key bytes should pass without deserialization");
        verify_crses(&storage, &crs_entries)
            .await
            .expect("matching raw CRS bytes should pass without deserialization");
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
        let metadata = material.current_metadata_with_types(&[PubDataType::CompressedXofKeySet]);

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
        for data_type in [PubDataType::PublicKey, PubDataType::ServerKey] {
            delete_data(&mut storage, &material.key_id, data_type).await;
            storage
                .store_bytes(
                    b"deliberately not a serialized TFHE key",
                    &material.key_id,
                    &data_type.to_string(),
                )
                .await
                .unwrap();
        }

        let entries = vec![(material.key_id, material.legacy_standard_metadata())];
        verify_keysets(&storage, &entries)
            .await
            .expect("legacy raw objects only need to be present");
    }

    #[tokio::test]
    async fn sanity_check_legacy_metadata_with_compressed_keyset_fails() {
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 50).await;
        let metadata = KeyGenMetadata::LegacyV0(HashMap::from_iter([
            (
                PubDataType::PublicKey,
                SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
            ),
            (
                PubDataType::CompressedXofKeySet,
                SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
            ),
        ]));

        let entries = vec![(material.key_id, metadata)];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE),
            "expected invalid legacy shape error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_legacy_metadata_with_only_public_key_fails() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 51).await;
        let metadata = KeyGenMetadata::LegacyV0(HashMap::from_iter([(
            PubDataType::PublicKey,
            SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
        )]));

        let entries = vec![(material.key_id, metadata)];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE),
            "expected invalid legacy shape error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_legacy_metadata_with_only_server_key_fails() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 52).await;
        let metadata = KeyGenMetadata::LegacyV0(HashMap::from_iter([(
            PubDataType::ServerKey,
            SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
        )]));

        let entries = vec![(material.key_id, metadata)];
        let err = verify_keysets(&storage, &entries).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE),
            "expected invalid legacy shape error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_crs_valid_digest() {
        let mut rng = AesRng::seed_from_u64(70);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let (_crs, digest) = setup_crs(&mut storage, &crs_id).await;

        let metadata = CrsGenMetadata::Current(crate::engine::base::CrsGenMetadataInner {
            crs_id,
            crs_digest: digest,
            max_num_bits: 64,
            extra_data: None,
            external_signature: vec![],
            signatures: vec![],
        });

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

        let (_crs, mut digest) = setup_crs(&mut storage, &crs_id).await;
        // Corrupt the digest
        digest[0] ^= 0xFF;

        let metadata = CrsGenMetadata::Current(crate::engine::base::CrsGenMetadataInner {
            crs_id,
            crs_digest: digest,
            max_num_bits: 64,
            extra_data: None,
            external_signature: vec![],
            signatures: vec![],
        });

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

        // Replace a valid fixture with bytes that cannot be decoded as a CRS. Legacy metadata
        // has no digest, so startup deliberately checks only that the raw object is present.
        let _crs_and_digest = setup_crs(&mut storage, &crs_id).await;
        delete_data(&mut storage, &crs_id, PubDataType::CRS).await;
        storage
            .store_bytes(
                b"deliberately not a serialized TFHE CRS",
                &crs_id,
                &PubDataType::CRS.to_string(),
            )
            .await
            .unwrap();

        use kms_grpc::rpc_types::SignedPubDataHandleInternal;
        let legacy_handle = SignedPubDataHandleInternal::new(String::new(), vec![], vec![]);
        let metadata = CrsGenMetadata::LegacyV0(legacy_handle);

        let entries = HashMap::from_iter([(crs_id, metadata)]);
        verify_crses(&storage, &entries)
            .await
            .expect("legacy raw CRS object only needs to be present");
    }

    // === A2 / B1: explicit presence errors ===

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
        let (_crs, digest) = setup_crs(&mut storage, &crs_id).await;
        delete_data(&mut storage, &crs_id, PubDataType::CRS).await;

        let entries =
            HashMap::from_iter([(crs_id, crs_metadata_with_signatures(&crs_id, digest, &[]).0)]);
        let err = verify_crses(&storage, &entries).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing or unreadable public material")
                && msg.contains(&PubDataType::CRS.to_string())
                && msg.contains(&crs_id.to_string()),
            "error should name the missing type and the crs id, got: {msg}"
        );
    }

    // === A5: keygen metadata signatures ===

    #[tokio::test]
    async fn keygen_signatures_verify_under_non_ecdsa_scheme() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 110).await;
        let (metadata, sk) = material.signed_metadata(&[SigningSchemeType::MlDsa65]);

        let skipped = verify_keygen_metadata_signatures(&sk, &material.key_id, &metadata)
            .expect("a freshly produced ML-DSA signature must verify");
        assert_eq!(skipped, 0, "no ECDSA signature was requested");
    }

    #[tokio::test]
    async fn keygen_signatures_reject_corrupted_signature() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 111).await;
        let (mut metadata, sk) = material.signed_metadata(&[SigningSchemeType::MlDsa65]);
        if let KeyGenMetadata::Current(inner) = &mut metadata {
            inner.signatures[0].signature[0] ^= 0xFF;
        }

        let err = verify_keygen_metadata_signatures(&sk, &material.key_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_SIGNATURE_INVALID),
            "expected a signature failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn keygen_signatures_reject_corrupted_digest_map() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 112).await;
        let (mut metadata, sk) = material.signed_metadata(&[SigningSchemeType::MlDsa65]);
        // The digest map is inside the signed payload, so corrupting it must be caught even
        // though the signature bytes are untouched.
        if let KeyGenMetadata::Current(inner) = &mut metadata
            && let Some(digest) = inner.key_digest_map.get_mut(&PubDataType::ServerKey)
        {
            digest[0] ^= 0xFF;
        }

        let err = verify_keygen_metadata_signatures(&sk, &material.key_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_SIGNATURE_INVALID),
            "expected a signature failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn keygen_signatures_skip_ecdsa_and_report_the_count() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 113).await;
        let (metadata, sk) = material.signed_metadata(&[SigningSchemeType::Ecdsa256k1]);

        let skipped = verify_keygen_metadata_signatures(&sk, &material.key_id, &metadata)
            .expect("an ECDSA-only signature list must be skipped, not rejected");
        assert_eq!(skipped, 1, "the ECDSA signature should be reported skipped");
    }

    #[tokio::test]
    async fn keygen_signatures_accept_empty_signature_list() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 114).await;
        // `signatures` defaults to empty, which is what most existing material looks like.
        let metadata = material.current_metadata();
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(114));

        let skipped = verify_keygen_metadata_signatures(&sk, &material.key_id, &metadata)
            .expect("no signatures means nothing to verify");
        assert_eq!(skipped, 0);
    }

    #[tokio::test]
    async fn keygen_signatures_skipped_for_legacy_metadata() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 115).await;
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(115));

        let skipped = verify_keygen_metadata_signatures(
            &sk,
            &material.key_id,
            &material.legacy_standard_metadata(),
        )
        .expect("legacy metadata carries no per-scheme signatures");
        assert_eq!(skipped, 0);
    }

    #[tokio::test]
    async fn keygen_metadata_stored_under_a_different_id_is_rejected() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 116).await;
        let (metadata, sk) = material.signed_metadata(&[SigningSchemeType::MlDsa65]);
        // A different seed than `setup_standard_keys` used, so this really is another ID.
        let other_id = RequestId::new_random(&mut AesRng::seed_from_u64(0xA116));
        assert_ne!(other_id, material.key_id);

        let err = verify_keygen_metadata_signatures(&sk, &other_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_ID_MISMATCH),
            "expected an ID mismatch, got: {err}"
        );
    }

    // === B4: CRS metadata signatures ===

    #[tokio::test]
    async fn crs_signatures_verify_under_non_ecdsa_scheme() {
        let mut rng = AesRng::seed_from_u64(120);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        let (_crs, digest) = setup_crs(&mut storage, &crs_id).await;
        let (metadata, sk) =
            crs_metadata_with_signatures(&crs_id, digest, &[SigningSchemeType::MlDsa65]);

        let skipped = verify_crs_metadata_signatures(&sk, &crs_id, &metadata)
            .expect("a freshly produced ML-DSA signature must verify");
        assert_eq!(skipped, 0);
    }

    #[tokio::test]
    async fn crs_signatures_reject_corrupted_signature() {
        let mut rng = AesRng::seed_from_u64(121);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        let (_crs, digest) = setup_crs(&mut storage, &crs_id).await;
        let (mut metadata, sk) =
            crs_metadata_with_signatures(&crs_id, digest, &[SigningSchemeType::MlDsa65]);
        if let CrsGenMetadata::Current(inner) = &mut metadata {
            inner.signatures[0].signature[0] ^= 0xFF;
        }

        let err = verify_crs_metadata_signatures(&sk, &crs_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_SIGNATURE_INVALID),
            "expected a signature failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn crs_signatures_reject_corrupted_digest() {
        let mut rng = AesRng::seed_from_u64(122);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        let (_crs, digest) = setup_crs(&mut storage, &crs_id).await;
        let (mut metadata, sk) =
            crs_metadata_with_signatures(&crs_id, digest, &[SigningSchemeType::MlDsa65]);
        if let CrsGenMetadata::Current(inner) = &mut metadata {
            inner.crs_digest[0] ^= 0xFF;
        }

        let err = verify_crs_metadata_signatures(&sk, &crs_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_SIGNATURE_INVALID),
            "expected a signature failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn crs_metadata_stored_under_a_different_id_is_rejected() {
        let mut rng = AesRng::seed_from_u64(123);
        let crs_id = RequestId::new_random(&mut rng);
        let other_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        let (_crs, digest) = setup_crs(&mut storage, &crs_id).await;
        let (metadata, sk) =
            crs_metadata_with_signatures(&crs_id, digest, &[SigningSchemeType::MlDsa65]);

        let err = verify_crs_metadata_signatures(&sk, &other_id, &metadata).unwrap_err();
        assert!(
            err.to_string().contains(ERR_METADATA_ID_MISMATCH),
            "expected an ID mismatch, got: {err}"
        );
    }

    // === C1 / C2: signing key material ===

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

    // === Extra material in public storage must be ignored ===

    #[tokio::test]
    async fn extra_verf_key_under_another_id_is_ignored() {
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
            .expect("an unrelated extra verification key must be ignored");
    }

    #[tokio::test]
    async fn orphan_public_material_is_ignored() {
        let mut storage = RamStorage::new();
        let mut rng = AesRng::seed_from_u64(141);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        store_signing_key_material(&mut storage, &sk, None).await;

        // Keysets and a CRS that private storage knows nothing about.
        let _orphan_standard = setup_standard_keys(&mut storage, 142).await;
        let _orphan_compressed = setup_compressed_keys(&mut storage, 143).await;
        let orphan_crs_id = RequestId::new_random(&mut rng);
        let _orphan_crs = setup_crs(&mut storage, &orphan_crs_id).await;

        verify_public_material(&storage, &[], &HashMap::new(), Some(&sk))
            .await
            .expect("material with no private counterpart must be ignored");
    }

    // === Recovery mode ===

    #[tokio::test]
    async fn without_signing_key_digests_still_run_and_key_checks_are_skipped() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 150).await;
        let entries = vec![(material.key_id, material.current_metadata())];

        // No VerfKey/VerfAddress stored at all, so this only passes because C is skipped.
        verify_public_material(&storage, &entries, &HashMap::new(), None)
            .await
            .expect("recovery mode skips the signing-key dependent checks");
    }

    #[tokio::test]
    async fn without_signing_key_digest_mismatch_is_still_fatal() {
        let mut storage = RamStorage::new();
        let mut material = setup_standard_keys(&mut storage, 151).await;
        if let Some(digest) = material.key_digest_map.get_mut(&PubDataType::ServerKey) {
            digest[0] ^= 0xFF;
        }
        let entries = vec![(material.key_id, material.current_metadata())];

        let err = verify_public_material(&storage, &entries, &HashMap::new(), None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_SERVER_KEY_DIGEST_MISMATCH),
            "digest verification must run even without a signing key, got: {err}"
        );
    }

    // === End to end ===

    #[tokio::test]
    async fn verify_public_material_accepts_consistent_storage() {
        let mut storage = RamStorage::new();
        let mut rng = AesRng::seed_from_u64(160);
        let material = setup_standard_keys(&mut storage, 161).await;
        let (metadata, sk) = material.signed_metadata(&[SigningSchemeType::MlDsa65]);
        store_signing_key_material(&mut storage, &sk, None).await;

        let crs_id = RequestId::new_random(&mut rng);
        let (_crs, crs_digest) = setup_crs(&mut storage, &crs_id).await;
        let (crs_metadata, _crs_sk) = crs_metadata_with_signatures_using(
            &sk,
            &crs_id,
            crs_digest,
            &[SigningSchemeType::MlDsa65],
        );

        let entries = vec![(material.key_id, metadata)];
        let crs_entries = HashMap::from_iter([(crs_id, crs_metadata)]);
        verify_public_material(&storage, &entries, &crs_entries, Some(&sk))
            .await
            .expect("consistent public storage must verify");
    }

    // === Helpers ===

    /// Write the `VerfKey` and `VerfAddress` a node publishes for its signing key.
    /// `address_override` lets a test store an address that does not match `sk`.
    async fn store_signing_key_material(
        storage: &mut RamStorage,
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

    /// Build CRS metadata signed under a fresh key, the way `crs_gen` would.
    fn crs_metadata_with_signatures(
        crs_id: &RequestId,
        crs_digest: Vec<u8>,
        schemes: &[SigningSchemeType],
    ) -> (CrsGenMetadata, PrivateSigKey) {
        let (_pk, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(0xC5));
        let (metadata, _) = crs_metadata_with_signatures_using(&sk, crs_id, crs_digest, schemes);
        (metadata, sk)
    }

    /// Build CRS metadata signed under a caller-supplied key.
    fn crs_metadata_with_signatures_using(
        sk: &PrivateSigKey,
        crs_id: &RequestId,
        crs_digest: Vec<u8>,
        schemes: &[SigningSchemeType],
    ) -> (CrsGenMetadata, PrivateSigKey) {
        let metadata = crate::engine::base::compute_info_crs_from_digest(
            sk,
            schemes,
            crs_id,
            crs_digest,
            64,
            &crate::dummy_domain(),
            vec![],
        )
        .unwrap();
        (metadata, sk.clone())
    }

    async fn setup_standard_keys(storage: &mut RamStorage, seed: u64) -> TestStoredMaterial {
        let mut rng = AesRng::seed_from_u64(seed);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let params = crate::consts::TEST_PARAM;
        let pbs_params: ClassicPBSParameters = params.classic_pbs();
        let config = tfhe::ConfigBuilder::with_custom_parameters(pbs_params);
        let client_key = tfhe::ClientKey::generate(config);
        let server_key = client_key.generate_server_key();
        let public_key = tfhe::CompactPublicKey::new(&client_key);

        let server_key_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &server_key).unwrap();
        let public_key_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &public_key).unwrap();

        store_versioned_at_request_id(
            storage,
            &key_id,
            &public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            storage,
            &key_id,
            &server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();

        TestStoredMaterial {
            key_id,
            preproc_id,
            key_digest_map: BTreeMap::from_iter([
                (PubDataType::ServerKey, server_key_digest),
                (PubDataType::PublicKey, public_key_digest),
            ]),
        }
    }

    async fn setup_compressed_keys(storage: &mut RamStorage, seed: u64) -> TestStoredMaterial {
        let mut rng = AesRng::seed_from_u64(seed);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let params = crate::consts::TEST_PARAM;
        let config = params.to_tfhe_config();
        let max_norm_hwt = params.sk_deviations().map(|x| x.pmax).unwrap_or(1.0);
        let max_norm_hwt = NormalizedHammingWeightBound::new(max_norm_hwt).unwrap();
        let tag = key_id.into();

        let (_client_key, compressed_keyset) = CompressedXofKeySet::generate(
            config,
            vec![42, 43, 44, 45],
            params.sec() as u32,
            max_norm_hwt,
            tag,
        )
        .unwrap();
        let compact_public_key = compressed_keyset.clone().decompress().into_raw_parts().0;

        let compressed_keyset_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &compressed_keyset).unwrap();
        let public_key_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &compact_public_key).unwrap();

        store_versioned_at_request_id(
            storage,
            &key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            storage,
            &key_id,
            &compact_public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();

        TestStoredMaterial {
            key_id,
            preproc_id,
            key_digest_map: BTreeMap::from_iter([
                (PubDataType::CompressedXofKeySet, compressed_keyset_digest),
                (PubDataType::PublicKey, public_key_digest),
            ]),
        }
    }

    async fn delete_data(storage: &mut RamStorage, key_id: &RequestId, data_type: PubDataType) {
        delete_at_request_id(storage, key_id, &data_type.to_string())
            .await
            .unwrap();
    }

    async fn setup_crs(
        storage: &mut RamStorage,
        crs_id: &RequestId,
    ) -> (tfhe::zk::CompactPkeCrs, Vec<u8>) {
        let mut rng = AesRng::seed_from_u64(42);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let params = crate::consts::TEST_PARAM;
        let domain = crate::dummy_domain();
        let max_num_bits = 64u32;

        let (crs, metadata) = gen_centralized_crs(
            &sk,
            &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
            &params,
            Some(max_num_bits),
            &domain,
            vec![],
            crs_id,
            &mut rng,
        )
        .unwrap();

        let digest = match &metadata {
            CrsGenMetadata::Current(inner) => inner.crs_digest.clone(),
            _ => panic!("expected Current metadata, instead got {:?}", metadata),
        };

        store_versioned_at_request_id(storage, crs_id, &crs, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        (crs, digest)
    }
}
