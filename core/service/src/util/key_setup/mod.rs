cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        pub mod test_tools;

        use crate::dummy_domain;
        use crate::engine::base::INSECURE_PREPROCESSING_ID;
        use crate::engine::base::{
            compute_info_compressed_keygen_from_digests, compute_info_crs_from_digest,
            CrsGenMetadata,
        };
        use crate::engine::base::{DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY};
        use crate::engine::centralized::central_kms::{gen_centralized_crs, generate_fhe_keys};
        use crate::engine::threshold::service::{PublicKeyMaterial, ThresholdFheKeys};
        use crate::vault::storage::crypto_material::{
            calculate_max_num_bits,  data_exists, get_core_signing_key,
        };
        use crate::vault::storage::crypto_material::check_data_exists_at_epoch;
        use crate::vault::storage::{delete_at_request_and_epoch_id, store_versioned_at_request_and_epoch_id, StorageExt};

        use hashing::hash_versioned;
        use futures_util::future;
        use itertools::Itertools;
        use kms_grpc::identifiers::EpochId;
        use std::sync::Arc;
        use tfhe::Seed;
        use threshold_execution::keyset_config::StandardKeySetConfig;
        use threshold_execution::tfhe_internals::parameters::DKGParams;
        use threshold_execution::tfhe_internals::test_feature::gen_key_set;
        use threshold_execution::tfhe_internals::test_feature::keygen_all_party_shares_from_client_key;
        use threshold_execution::zk::ceremony::{max_num_bits_from_crs, public_parameters_by_trusted_setup};
        use threshold_types::session_id::SessionId;
    }
}

use crate::anyhow_error_and_log;
use crate::client::client_non_wasm::ClientDataType;
use crate::consts::{SIGNING_KEY_ID, signing_material_id};
use crate::cryptography::signatures::{PrivateSigKey, SigningSchemeType, gen_sig_keys};
use crate::cryptography::signing::UnifiedPublicSigKey;
use crate::cryptography::signing::seed::RootSigningSeed;
use crate::engine::base::compute_handle;
use crate::vault::storage::crypto_material::{
    get_core_root_signing_seed, get_rng, log_data_exists, log_storage_success,
    read_verification_key_at, store_verification_key_at,
};
use crate::vault::storage::{
    Storage, StorageReader, StorageType, delete_at_request_id, file::FileStorage,
    read_all_data_versioned, read_text_at_request_id, store_text_at_request_id,
    store_versioned_at_request_id,
};
use k256::pkcs8::EncodePrivateKey;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;
use strum::IntoEnumIterator;

/// Compact public key for FHE operations
pub type FhePublicKey = tfhe::CompactPublicKey;

/// Client key for FHE operations (contains private parameters)
pub type FhePrivateKey = tfhe::ClientKey;

/// Generates and stores client signing and verification keys if they don't exist.
///
/// This function handles the complete key setup workflow for clients:
/// 1. Initializes client storage
/// 2. Checks for existing keys
/// 3. Generates new keys if needed
/// 4. Stores private and public keys at the fixed [`SIGNING_KEY_ID`] handle
///
/// # Returns
/// - `true` if new keys were generated
/// - `false` if keys already existed or an error occurred
///
/// # Note
/// Primarily used for testing and debugging via the [Client].
///
/// # Panics
/// - If storage initiation fails
/// - If key generation or storage operations fail
/// - If handle computation fails
pub async fn ensure_client_keys_exist(optional_path: Option<&Path>, deterministic: bool) -> bool {
    let req_id = &*SIGNING_KEY_ID;
    // Initialize client storage with error handling
    let mut client_storage = match FileStorage::new(optional_path, StorageType::CLIENT, None) {
        Ok(storage) => storage,
        Err(e) => {
            panic!("Failed to create client storage: {e}");
        }
    };

    // Check if keys already exist with error handling
    let temp: HashMap<RequestId, PrivateSigKey> =
        match read_all_data_versioned(&client_storage, &ClientDataType::SigningKey.to_string())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!("Failed to read existing client signing keys: {}", e);
                return false;
            }
        };

    if !temp.is_empty() {
        // If signing keys already exist, then do nothing
        let storage_path = client_storage.root_dir().to_string_lossy();
        tracing::info!(
            "Client signing keys already exist at {}, skipping generation",
            storage_path
        );
        return false;
    }

    // Generate new signing key pair
    let mut rng = get_rng(deterministic, None);
    let (client_pk, client_sk) = gen_sig_keys(&mut rng);

    // Store private client key with error handling
    if let Err(e) = store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_sk,
        &ClientDataType::SigningKey.to_string(),
    )
    .await
    {
        panic!("Failed to store private client key: {e}");
    }
    log_storage_success(req_id, client_storage.info(), "client key", false, false);

    // Compute handle with error handling
    let pk_handle = match compute_handle(&client_pk) {
        Ok(handle) => handle,
        Err(e) => {
            panic!("Failed to compute handle for client public key: {e}");
        }
    };

    // Store public client key with error handling
    if let Err(e) = store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_pk,
        &ClientDataType::VerfKey.to_string(),
    )
    .await
    {
        panic!("Failed to store public client key: {e}");
    }
    log_storage_success(pk_handle, client_storage.info(), "client key", true, false);

    true
}

/// Ensures central server signing and verification keys exist.
///
/// The signing key and the root signing seed both live at the fixed
/// [`SIGNING_KEY_ID`] handle. If the signing key already exists, it is left
/// untouched and only what is missing around it is
/// completed. Otherwise a root seed is generated, the ECDSA key is derived
/// from it, and both are stored together with the verification material of
/// every signing scheme.
///
/// # Returns
/// - `Ok(true)` if new keys were generated
/// - `Ok(false)` if a signing key already existed
/// - `Err` if reading, generating or storing any of the material failed
pub async fn ensure_central_server_signing_keys_exist<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    #[cfg(any(test, feature = "testing", feature = "insecure"))] deterministic: bool,
) -> anyhow::Result<bool>
where
    PubS: Storage,
    PrivS: Storage,
{
    // Check if keys already exist
    let signing_keys_map: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read existing server signing keys: {e}"))?;

    #[cfg(any(test, feature = "testing", feature = "insecure"))]
    let mut rng = get_rng(deterministic, Some(0));
    #[cfg(not(any(test, feature = "testing", feature = "insecure")))]
    let mut rng = get_rng(false, Some(0));

    if let Some(sk) = signing_keys_map.get(&*SIGNING_KEY_ID) {
        // If a signing key already exists under this request ID, then only the
        // public verification material may still need to be written
        log_data_exists(
            priv_storage.info(),
            Some(pub_storage.info()),
            *SIGNING_KEY_ID,
            "Server signing keys",
        );
        // An upgraded node keeps the ECDSA key it is registered under; all it
        // may still be missing is the root the *other* schemes derive from.
        let seed = ensure_root_signing_seed(pub_storage, priv_storage, &mut rng).await?;
        let sk = sk.clone().with_root_seed(seed);
        ensure_published_verification_material(pub_storage, &sk).await?;

        return Ok(false);
    }

    if !signing_keys_map.is_empty() {
        tracing::warn!(
            "Existing signing keys found under other request IDs but none under request ID {}, generating new keys",
            *SIGNING_KEY_ID
        );
    }

    // Reject a storage that still holds material derived from a previous signing
    // key. We already checked no signing key exists so if verification material
    // exist it means inconsistent storage.
    ensure_no_scheme_verification_material(pub_storage).await?;
    ensure_no_root_signing_seed(priv_storage).await?;

    let sk =
        generate_and_store_signing_key_material(pub_storage, priv_storage, &mut rng, false).await?;

    // Persist every scheme's verification material, ECDSA's included, from the
    // freshly generated ECDSA signing key.
    ensure_published_verification_material(pub_storage, &sk)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store scheme verification material: {e}"))?;

    Ok(true)
}

/// Generates a fresh signing identity and persists it at [`SIGNING_KEY_ID`]: the
/// root seed, and the ECDSA key derived from it together with its verification
/// material (public key, Ethereum address, private key).
///
/// Callers must first confirm no signing key already exists, that public storage
/// holds no leftover verification material (via
/// [`ensure_no_scheme_verification_material`]) and that no seed is left behind
/// (via [`ensure_no_root_signing_seed`]).
async fn generate_and_store_signing_key_material<PubS, PrivS, R>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    rng: &mut R,
    is_threshold: bool,
) -> anyhow::Result<PrivateSigKey>
where
    PubS: Storage,
    PrivS: Storage,
    R: rand::CryptoRng + rand::Rng,
{
    let seed = RootSigningSeed::random(rng);
    let sk = seed.derive_ecdsa_signing_key().map_err(|e| {
        anyhow::anyhow!("Failed to derive the ECDSA signing key from the seed: {e}")
    })?;
    let pk = sk.verf_key();

    // The seed is written first, before anything derived from it,
    // such that if something goes wrong things will fail loudly at boot
    // since no signing key will be present.
    store_versioned_at_request_id(
        priv_storage,
        &SIGNING_KEY_ID,
        &seed,
        &PrivDataType::SigningSeed.to_string(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to store the root signing seed: {e}"))?;

    // Store public verification key
    store_versioned_at_request_id(
        pub_storage,
        &SIGNING_KEY_ID,
        &pk,
        &PubDataType::VerfKey.to_string(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to store public verification key: {e}"))?;

    let ethereum_address = pk.address();

    // Store ethereum address (derived from public key), needed for KMS signature verification
    store_text_at_request_id(
        pub_storage,
        &SIGNING_KEY_ID,
        &ethereum_address.to_string(),
        &PubDataType::VerfAddress.to_string(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to store ethereum address: {e}"))?;
    tracing::info!(
        "Successfully stored ethereum address {} under the handle {} in storage \"{}\"",
        ethereum_address,
        *SIGNING_KEY_ID,
        pub_storage.info()
    );

    // Store private signing key
    store_versioned_at_request_id(
        priv_storage,
        &SIGNING_KEY_ID,
        &sk,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to store private signing key: {e}"))?;
    log_storage_success(
        *SIGNING_KEY_ID,
        priv_storage.info(),
        "server signing key",
        false,
        is_threshold,
    );

    Ok(sk.with_root_seed(seed))
}

/// The node's root signing seed, generating and persisting one if it has none.
///
/// This is the **only** place a seed is ever created. It is an explicit,
/// operator-driven step — running `kms-gen-keys` — and never something a restart
/// does on its own: the boot migration warns and skips instead, so a node's
/// post-quantum identity is never minted by an unattended process.
///
/// A newly created seed is not yet in the backup vault. The boot pass that copies
/// it there runs on the next start, so nothing derived from it should be
/// published to peers until that has happened.
async fn ensure_root_signing_seed<PubS, PrivS, R>(
    pub_storage: &PubS,
    priv_storage: &mut PrivS,
    rng: &mut R,
) -> anyhow::Result<RootSigningSeed>
where
    PubS: StorageReader,
    PrivS: Storage,
    R: rand::CryptoRng + rand::Rng,
{
    if let Some(seed) = get_core_root_signing_seed(priv_storage).await? {
        return Ok(seed);
    }

    if non_ecdsa_scheme_material_exists(pub_storage).await? {
        return Err(anyhow_error_and_log(format!(
            "public storage already holds non-ECDSA verification material, but the {} object \
             under the handle {} is missing.",
            PrivDataType::SigningSeed,
            *SIGNING_KEY_ID
        )));
    }

    let seed = RootSigningSeed::random(rng);
    store_versioned_at_request_id(
        priv_storage,
        &SIGNING_KEY_ID,
        &seed,
        &PrivDataType::SigningSeed.to_string(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to store the root signing seed: {e}"))?;
    tracing::info!(
        "Generated a root signing seed under the handle {} in storage \"{}\". \
         Every non-ECDSA identity of this node derives from it and it is stored \
         nowhere else, so it must reach the backup vault before anything derived \
         from it is published.",
        *SIGNING_KEY_ID,
        priv_storage.info()
    );
    Ok(seed)
}

/// Reject a storage that holds a root signing seed but no signing key.
///
/// The two are generated together — and `kms-gen-keys --overwrite` deletes both —
/// so a seed on its own means an interrupted run or a partial wipe. Generating a
/// fresh identity next to it would leave the persisted seed paired with an ECDSA
/// key it did not produce, and deriving the new key *from* it would silently
/// resurrect an identity the operator may have meant to destroy — so neither is
/// done automatically.
async fn ensure_no_root_signing_seed<PrivS: StorageReader>(
    priv_storage: &PrivS,
) -> anyhow::Result<()> {
    if priv_storage
        .data_exists(&SIGNING_KEY_ID, &PrivDataType::SigningSeed.to_string())
        .await?
    {
        return Err(anyhow_error_and_log(format!(
            "a root signing seed already exists under the handle {} but the signing key it \
             belongs to does not; delete the {} object as well before regenerating",
            *SIGNING_KEY_ID,
            PrivDataType::SigningSeed
        )));
    }
    Ok(())
}

/// One published verification object: which folder it lives in, under which
/// handle, and which scheme's key it describes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MaterialSlot {
    scheme: SigningSchemeType,
    req_id: RequestId,
    folder: PubDataType,
}

impl MaterialSlot {
    /// Whether the slot holds the verification key itself rather than its digest.
    fn holds_key(self) -> bool {
        matches!(
            self.folder,
            PubDataType::VerfKey | PubDataType::TypedVerfKey
        )
    }

    /// The storage folder name this slot lives in.
    fn data_type(self) -> String {
        self.folder.to_string()
    }

    /// Whether anything is published in this slot.
    async fn exists<S: StorageReader>(self, storage: &S) -> anyhow::Result<bool> {
        storage.data_exists(&self.req_id, &self.data_type()).await
    }

    /// Whether this slot already holds exactly what `verf_key` implies.
    async fn matches<S: StorageReader>(
        self,
        storage: &S,
        verf_key: &UnifiedPublicSigKey,
    ) -> anyhow::Result<bool> {
        if self.holds_key() {
            let stored =
                read_verification_key_at(storage, &self.req_id, self.folder, self.scheme).await?;
            Ok(&stored == verf_key)
        } else {
            let stored = read_text_at_request_id(storage, &self.req_id, &self.data_type()).await?;
            Ok(stored == verf_key.address_text())
        }
    }

    /// Write what `verf_key` implies into this slot.
    async fn write<S: Storage>(
        self,
        storage: &mut S,
        verf_key: &UnifiedPublicSigKey,
    ) -> anyhow::Result<()> {
        if self.holds_key() {
            store_verification_key_at(storage, &self.req_id, self.folder, verf_key).await
        } else {
            store_text_at_request_id(
                storage,
                &self.req_id,
                &verf_key.address_text(),
                &self.data_type(),
            )
            .await
        }
    }

    /// Remove whatever is published in this slot. Absent material is not an error.
    async fn delete<S: Storage>(self, storage: &mut S) -> anyhow::Result<()> {
        delete_at_request_id(storage, &self.req_id, &self.data_type())
            .await
            .map_err(|e| anyhow_error_and_log(format!("Failed to delete {self}: {e}")))
    }
}

impl std::fmt::Display for MaterialSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} under the handle {}",
            self.scheme, self.folder, self.req_id
        )
    }
}

/// The public data types holding a scheme's verification material.
pub const CURRENT_VERF_MATERIAL_TYPES: [PubDataType; 2] =
    [PubDataType::TypedVerfKey, PubDataType::TypedVerfAddress];

/// The deprecated ECDSA-only location of a node's published identity: a bare
/// `PublicSigKey` and a checksummed Ethereum address.
pub const LEGACY_VERF_MATERIAL_TYPES: [PubDataType; 2] =
    [PubDataType::VerfKey, PubDataType::VerfAddress];

/// Every public key based verification object a node publishes excluding
/// the deprecated ECDSA-only pair under [`SIGNING_KEY_ID`].
pub(crate) fn non_legacy_verf_material_slots() -> impl Iterator<Item = MaterialSlot> {
    SigningSchemeType::iter().flat_map(|scheme| {
        CURRENT_VERF_MATERIAL_TYPES.map(move |folder| MaterialSlot {
            scheme,
            req_id: signing_material_id(scheme),
            folder,
        })
    })
}

/// Every public key based verification object a node publishes:
/// the canonical per-scheme material, including the deprecated ECDSA-only pair under [`SIGNING_KEY_ID`].
pub(crate) fn all_verf_material_slots() -> impl Iterator<Item = MaterialSlot> {
    non_legacy_verf_material_slots().chain(LEGACY_VERF_MATERIAL_TYPES.map(|folder| MaterialSlot {
        scheme: SigningSchemeType::Ecdsa256k1,
        req_id: *SIGNING_KEY_ID,
        folder,
    }))
}

/// The first slot of `slots` that already holds something, if any.
async fn first_existing_slot<S, I>(storage: &S, slots: I) -> anyhow::Result<Option<MaterialSlot>>
where
    S: StorageReader,
    I: Iterator<Item = MaterialSlot>,
{
    for slot in slots {
        if slot.exists(storage).await? {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// Check each slot of `slots` that holds something against `sk`.
pub(crate) async fn validate_slots<PubS, I>(
    pub_storage: &PubS,
    sk: &PrivateSigKey,
    slots: I,
) -> anyhow::Result<()>
where
    PubS: StorageReader,
    I: Iterator<Item = MaterialSlot>,
{
    let mut verf_keys: BTreeMap<SigningSchemeType, UnifiedPublicSigKey> = BTreeMap::new();

    for slot in slots {
        if !slot.exists(pub_storage).await? {
            continue;
        }
        if let std::collections::btree_map::Entry::Vacant(e) = verf_keys.entry(slot.scheme) {
            let verf_key = sk.unified_verifying_key(slot.scheme).map_err(|e| {
                anyhow_error_and_log(format!(
                    "the {slot} is published, but this node cannot derive the {} verification \
                      key to check it against: {e}",
                    slot.scheme
                ))
            })?;
            e.insert(verf_key);
        }
        if !slot.matches(pub_storage, &verf_keys[&slot.scheme]).await? {
            return Err(anyhow_error_and_log(format!(
                "the stored {slot} does not match the provided signing key"
            )));
        }
    }
    Ok(())
}

/// Publish every verification object the signing identity `sk` implies, and check
/// every one already published against it.
///
/// Nothing is ever overwritten. Anything already published has to agree with `sk`,
/// and *every* slot is checked before *any* is written, so a mismatch leaves
/// storage exactly as it was rather than half-updated.
pub async fn ensure_published_verification_material<PubS>(
    pub_storage: &mut PubS,
    sk: &PrivateSigKey,
) -> anyhow::Result<()>
where
    PubS: Storage,
{
    validate_slots(pub_storage, sk, all_verf_material_slots()).await?;

    // Derived once per scheme rather than once per slot. Unlike the validation
    // pass this covers every scheme, because every scheme is about to be written.
    let mut verf_keys = BTreeMap::new();
    for scheme in SigningSchemeType::iter() {
        let verf_key = sk.unified_verifying_key(scheme).map_err(|e| {
            anyhow_error_and_log(format!("could not derive {scheme} verification key: {e}"))
        })?;
        verf_keys.insert(scheme, verf_key);
    }

    for slot in all_verf_material_slots() {
        if slot.exists(pub_storage).await? {
            continue;
        }
        slot.write(pub_storage, &verf_keys[&slot.scheme])
            .await
            .map_err(|e| anyhow_error_and_log(format!("failed to store the {slot}: {e}")))?;
        tracing::info!("Stored {slot} in storage \"{}\"", pub_storage.info());
    }
    Ok(())
}

/// Validate that no canonical scheme verification material is present.
pub async fn ensure_no_scheme_verification_material<PubS>(pub_storage: &PubS) -> anyhow::Result<()>
where
    PubS: StorageReader,
{
    match first_existing_slot(pub_storage, non_legacy_verf_material_slots()).await? {
        Some(slot) => Err(anyhow_error_and_log(format!(
            "data already exist for {slot}"
        ))),
        None => Ok(()),
    }
}

/// Checks whether public storage holds verification material for any scheme other than
/// ECDSA.
async fn non_ecdsa_scheme_material_exists<PubS>(pub_storage: &PubS) -> anyhow::Result<bool>
where
    PubS: StorageReader,
{
    let non_ecdsa = non_legacy_verf_material_slots()
        .filter(|slot| slot.scheme != SigningSchemeType::Ecdsa256k1);
    Ok(first_existing_slot(pub_storage, non_ecdsa).await?.is_some())
}

/// Delete every scheme's canonical verification material, ECDSA's included.
///
/// The deprecated ECDSA-only pair is deliberately *not* touched here, so a caller
/// can purge the per-scheme layout alone. Callers wiping the whole identity want
/// [`delete_published_verification_material`] instead.
pub async fn delete_scheme_verification_material<PubS>(pub_storage: &mut PubS) -> anyhow::Result<()>
where
    PubS: Storage,
{
    for slot in non_legacy_verf_material_slots() {
        slot.delete(pub_storage).await?;
    }
    Ok(())
}

/// Delete every verification object a node publishes, deprecated ECDSA-only pair included.
pub async fn delete_published_verification_material<PubS>(
    pub_storage: &mut PubS,
) -> anyhow::Result<()>
where
    PubS: Storage,
{
    for slot in all_verf_material_slots() {
        slot.delete(pub_storage).await?;
    }
    Ok(())
}

/// Store a caller-supplied server signing key together with the public verification key and
/// Ethereum address it implies, all at the fixed [`SIGNING_KEY_ID`] handle.
#[cfg(any(test, feature = "testing"))]
pub async fn store_server_signing_keys<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    sk: &PrivateSigKey,
) -> anyhow::Result<()>
where
    PubS: Storage,
    PrivS: Storage,
{
    let req_id = &*SIGNING_KEY_ID;
    let pk = sk.verf_key();
    store_versioned_at_request_id(pub_storage, req_id, &pk, &PubDataType::VerfKey.to_string())
        .await?;
    store_text_at_request_id(
        pub_storage,
        req_id,
        &pk.address().to_string(),
        &PubDataType::VerfAddress.to_string(),
    )
    .await?;
    store_versioned_at_request_id(
        priv_storage,
        req_id,
        sk,
        &PrivDataType::SigningKey.to_string(),
    )
    .await?;
    Ok(())
}

/// Generates and stores a Common Reference String (CRS) if it doesn't exist.
///
/// Handles the complete CRS lifecycle:
/// 1. Validates storage consistency
/// 2. Checks for existing CRS
/// 3. Generates new CRS with the given parameters
/// 4. Stores both public CRS and private metadata
///
/// # Returns
/// - `true` if new CRS was generated
/// - `false` if CRS already existed
///
/// # Panics
/// - If storage validation fails
/// - If CRS generation fails
/// - If storage operations fail
#[cfg(any(test, feature = "testing"))]
pub async fn ensure_central_crs_exists<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    dkg_params: DKGParams,
    crs_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    // Check if data already exists in both storages
    match check_data_exists_at_epoch(
        pub_storage,
        priv_storage,
        crs_id,
        epoch_id,
        &PubDataType::CRS,
        &PrivDataType::CrsInfo,
    )
    .await
    {
        Ok(true) => {
            return false;
        }
        Ok(false) => {
            // continue with generation
            tracing::info!("CRS does not exist, proceeding with generation.");
        }
        Err(e) => {
            tracing::warn!("Failed to check if CRS exists, proceeding with generation anyway: {e}");
        }
    }

    // Get signing key with proper error handling
    let sk = match get_core_signing_key(priv_storage).await {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("Failed to get signing key: {}", e);
            return false; // Cannot proceed without signing key
        }
    };
    let mut rng = get_rng(deterministic, Some(0));

    // Calculate max_num_bits based on DKG parameters - now handles errors internally
    let max_num_bits = calculate_max_num_bits(&dkg_params);

    // Convert usize to Option<u32> for gen_centralized_crs
    let max_num_bits_u32 = Some(max_num_bits as u32);

    // Use proper error handling instead of unwrap
    let domain = dummy_domain();
    let (pp, crs_info) = match gen_centralized_crs(
        &sk,
        &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
        &dkg_params,
        max_num_bits_u32,
        &domain,
        vec![],
        crs_id,
        &mut rng,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate centralized CRS: {}", e);
            return false; // Cannot proceed without CRS
        }
    };

    // Store private CRS info with proper error handling
    if let Err(e) = store_versioned_at_request_and_epoch_id(
        priv_storage,
        crs_id,
        epoch_id,
        &crs_info,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    {
        tracing::error!("Failed to store private CRS info: {}", e);
        return false; // Storage operation failed
    }
    log_storage_success(crs_id, priv_storage.info(), "CRS data", false, false);

    // Store public CRS with proper error handling
    if let Err(e) =
        store_versioned_at_request_id(pub_storage, crs_id, &pp, &PubDataType::CRS.to_string()).await
    {
        tracing::error!("Failed to store public CRS: {}", e);
        return false; // Storage operation failed
    }
    log_storage_success(crs_id, pub_storage.info(), "CRS data", true, false);

    true
}

/// Ensures central server FHE keys exist.
///
/// Manages the complete FHE key lifecycle:
/// 1. Validates storage consistency
/// 2. Checks for existing keys
/// 3. Generates new key pairs with the given parameters
/// 4. Stores both public and private keys with metadata
/// 5. Manages two distinct key sets under [key_id] and [other_key_id]
///
/// # Returns
/// - `true` if new keys were generated
/// - `false` if keys already existed
///
/// # Panics
/// - If storage validation fails
/// - If key generation fails
/// - If storage operations fail
#[cfg(any(test, feature = "testing"))]
pub async fn ensure_central_keys_exist<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    dkg_params: DKGParams,
    key_id: &RequestId,
    other_key_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    // Check if PUBLIC data already exists. If so, skip regeneration entirely.
    //
    // Key generation uses seed-based XOF expansion, making it non-deterministic
    // across calls unless the same seed is used. If PUB keys exist but PRIV was
    // purged (e.g., for backup recovery tests), regenerating would create keys
    // with different digests that don't match the existing PUB data (since
    // store_data doesn't overwrite). The missing PRIV data will be restored
    // from backup.
    let compressed_xof_keyset_type = PubDataType::CompressedXofKeySet.to_string();
    let pub_types_to_purge = [
        compressed_xof_keyset_type.clone(),
        PubDataType::PublicKey.to_string(),
        PubDataType::ServerKey.to_string(),
    ];
    let pub_complete = data_exists(pub_storage, key_id, &compressed_xof_keyset_type)
        .await
        .unwrap_or(false)
        && data_exists(pub_storage, other_key_id, &compressed_xof_keyset_type)
            .await
            .unwrap_or(false);
    if pub_complete {
        log_data_exists(
            priv_storage.info(),
            Some(pub_storage.info()),
            key_id,
            "FHE keys",
        );
        return false;
    }

    // PUB data is incomplete — purge any leftover fragments and regenerate everything.
    for existing_pub_type in &pub_types_to_purge {
        let _ = delete_at_request_id(pub_storage, key_id, existing_pub_type).await;
        let _ = delete_at_request_id(pub_storage, other_key_id, existing_pub_type).await;
    }
    let _ = delete_at_request_and_epoch_id(
        priv_storage,
        key_id,
        epoch_id,
        &PrivDataType::FhePrivateKey.to_string(),
    )
    .await;

    // Get signing key with proper error handling
    let sk = match get_core_signing_key(priv_storage).await {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("Failed to get signing key: {}", e);
            return false; // Cannot proceed without signing key
        }
    };

    let seed = match deterministic {
        true => Some(Seed(42)),
        false => None,
    };

    // Generate the two FHE key sets in parallel on the rayon pool.
    let key_id_1 = *key_id;
    let key_id_2 = *other_key_id;
    let sk_1 = sk.clone();
    let sk_2 = sk;
    let (fhekey1, fhekey2) = tokio::task::spawn_blocking(move || {
        rayon::join(
            || {
                generate_fhe_keys(
                    &sk_1,
                    &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
                    dkg_params,
                    StandardKeySetConfig::default().secret_key_config,
                    &key_id_1,
                    &INSECURE_PREPROCESSING_ID,
                    seed,
                    &dummy_domain(),
                    vec![],
                )
            },
            || {
                generate_fhe_keys(
                    &sk_2,
                    &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
                    dkg_params,
                    StandardKeySetConfig::default().secret_key_config,
                    &key_id_2,
                    &INSECURE_PREPROCESSING_ID,
                    seed,
                    &dummy_domain(),
                    vec![],
                )
            },
        )
    })
    .await
    .expect("FHE keygen task panicked");

    let (compressed_keyset_1, public_key_1, key_info_1) = match fhekey1 {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate first set of FHE keys: {}", e);
            return false;
        }
    };
    let (compressed_keyset_2, public_key_2, key_info_2) = match fhekey2 {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate second set of FHE keys: {}", e);
            return false;
        }
    };

    let priv_fhe_map = HashMap::from([(*key_id, key_info_1), (*other_key_id, key_info_2)]);
    let pub_fhe_map = HashMap::from([
        (*key_id, (compressed_keyset_1, public_key_1)),
        (*other_key_id, (compressed_keyset_2, public_key_2)),
    ]);

    // Store private key data. The centralized service reads back this slot as
    // a `KmsFheKeyHandles`, so the bundled `key_info` is the value we persist
    // (despite the type tag being named `FhePrivateKey`).
    for (req_id, key_info) in &priv_fhe_map {
        if let Err(e) = store_versioned_at_request_and_epoch_id(
            priv_storage,
            req_id,
            epoch_id,
            key_info,
            &PrivDataType::FhePrivateKey.to_string(),
        )
        .await
        {
            tracing::error!("Failed to store key info for request ID {}: {}", req_id, e);
            continue; // Skip this key but try others
        }
        log_storage_success(req_id, priv_storage.info(), "key data", false, false);
    }

    // Store compressed keyset and the public key derived from it as public key data
    for (req_id, (compressed_keyset, public_key)) in pub_fhe_map {
        tracing::info!("Storing compressed keyset");
        if let Err(e) = store_versioned_at_request_id(
            pub_storage,
            &req_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store compressed keyset for request ID {}: {}",
                req_id,
                e
            );
            continue; // Skip this key but try others
        }
        log_storage_success(req_id, pub_storage.info(), "compressed keyset", true, false);

        if let Err(e) = store_versioned_at_request_id(
            pub_storage,
            &req_id,
            &public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store public key for request ID {}: {}",
                req_id,
                e
            );
            continue;
        }
        log_storage_success(req_id, pub_storage.info(), "public key", true, false);
    }
    true
}

/// Configuration for threshold signing key generation.
///
/// Defines the signing participation model for the threshold system.
pub enum ThresholdSigningKeyConfig {
    /// All parties participate in signing (requires list of party identifiers)
    AllParties(Vec<String>),
}

/// Generates and stores threshold server signing and verification keys.
///
/// Implements the complete threshold key setup workflow:
/// 1. Validates that the public and private storages line up with the parties
/// 2. Delegates to [`ensure_threshold_server_signing_key_exists`] for each
///    party, which either generates the party's key material or completes the
///    public material of the key it already has at [`SIGNING_KEY_ID`]
///
/// # Returns
/// - `Ok(())` if new keys were generated or keys already existed
/// - `Err` if reading, generating or storing any party's material failed
///
/// # Panics
/// - If the number of public and private storages differ
/// - If there are more configured parties than storages
pub async fn ensure_threshold_server_signing_keys_exist<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    #[cfg(any(test, feature = "testing", feature = "insecure"))] deterministic: bool,
    config: ThresholdSigningKeyConfig,
    tls_wildcard: bool,
) -> anyhow::Result<()>
where
    PubS: Storage,
    PrivS: Storage,
{
    // Validate input parameters
    if pub_storages.len() != priv_storages.len() {
        let msg = format!(
            "Number of public storages ({}) and private storages ({}) must be equal",
            pub_storages.len(),
            priv_storages.len()
        );
        tracing::error!(msg);
        panic!("{}", msg);
    }

    let ThresholdSigningKeyConfig::AllParties(parties) = config;

    // Validate party indices
    for i in 1..=parties.len() {
        if i > pub_storages.len() {
            let msg = format!(
                "Invalid party index: {} (must be between 1 and {})",
                i,
                pub_storages.len()
            );
            tracing::error!(msg);
            panic!("{}", msg);
        }
    }

    for (storage_index, subject) in parties.into_iter().enumerate() {
        ensure_threshold_server_signing_key_exists(
            &mut pub_storages[storage_index],
            &mut priv_storages[storage_index],
            #[cfg(any(test, feature = "testing", feature = "insecure"))]
            deterministic,
            // 1-based party id; NonZeroUsize by construction (saturates on overflow).
            // computes storage_index + 1
            std::num::NonZeroUsize::MIN.saturating_add(storage_index),
            subject,
            tls_wildcard,
        )
        .await?;
    }
    Ok(())
}

/// Generates and stores the threshold server signing and verification key for
/// one configured storage.
///
/// This is used by deployment paths where the storage backend already selects
/// the physical party destination (for example with a per-party storage
/// prefix). The `party_id` remains the logical 1-based party identifier used
/// for deterministic test seeding and certificate/log context; the
/// `NonZeroUsize` type enforces at the boundary that it cannot be 0.
///
/// If a signing key already exists at [`SIGNING_KEY_ID`], it is left untouched and
/// only what is missing around it is completed: a root signing seed if the node has
/// none, the verification material of every signing scheme, and the self-signed CA
/// certificate. Otherwise all of it is generated fresh, with the ECDSA key derived
/// from a newly generated root seed.
///
/// # Returns
/// - `Ok(true)` if new keys were generated
/// - `Ok(false)` if a signing key already existed
/// - `Err` if reading, generating or storing any of the material failed
pub async fn ensure_threshold_server_signing_key_exists<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    #[cfg(any(test, feature = "testing", feature = "insecure"))] deterministic: bool,
    party_id: std::num::NonZeroUsize,
    subject: String,
    tls_wildcard: bool,
) -> anyhow::Result<bool>
where
    PubS: Storage,
    PrivS: Storage,
{
    #[cfg(any(test, feature = "testing", feature = "insecure"))]
    let mut rng = get_rng(deterministic, Some(party_id.get() as u64));
    #[cfg(not(any(test, feature = "testing", feature = "insecure")))]
    let mut rng = get_rng(false, Some(party_id.get() as u64));

    // Check if keys already exist with error handling
    let signing_keys_map: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read existing server signing keys for party {}: {}",
                    party_id,
                    e
                )
            })?;

    if let Some(sk) = signing_keys_map.get(&*SIGNING_KEY_ID) {
        // If a signing key already exists under this request ID, then only the
        // public material may still need to be written
        log_data_exists(
            priv_storage.info(),
            Some(pub_storage.info()),
            *SIGNING_KEY_ID,
            "Threshold server signing keys",
        );

        // An upgraded node keeps the ECDSA key it is registered under; all it
        // may still be missing is the root the *other* schemes derive from.
        let seed = ensure_root_signing_seed(pub_storage, priv_storage, &mut rng)
            .await
            .map_err(|e| anyhow::anyhow!("Party {party_id}: {e}"))?;
        let sk = sk.clone().with_root_seed(seed);

        // Even if the signing key exists, its verification material might not
        ensure_published_verification_material(pub_storage, &sk)
            .await
            .map_err(|e| anyhow::anyhow!("Party {party_id}: {e}"))?;

        // Regenerate CA certificate if missing
        if !pub_storage
            .data_exists(&SIGNING_KEY_ID, &PubDataType::CACert.to_string())
            .await?
        {
            ensure_ca_cert_exists(pub_storage, &sk, subject, tls_wildcard).await?;
        }

        return Ok(false);
    }

    if !signing_keys_map.is_empty() {
        tracing::warn!(
            "Existing signing keys for party {} found under other request IDs but none under request ID {}, generating new keys",
            party_id,
            *SIGNING_KEY_ID
        );
    }

    // Reject a storage that still holds material derived from a previous signing
    // key. We already checked no signing key exists so if verification material
    // exist it means inconsistent storage.
    ensure_no_scheme_verification_material(pub_storage)
        .await
        .map_err(|e| anyhow::anyhow!("Party {party_id}: {e}"))?;
    ensure_no_root_signing_seed(priv_storage)
        .await
        .map_err(|e| anyhow::anyhow!("Party {party_id}: {e}"))?;

    let sk = generate_and_store_signing_key_material(pub_storage, priv_storage, &mut rng, true)
        .await
        .map_err(|e| anyhow::anyhow!("Party {party_id}: {e}"))?;

    // Generate CA certificate
    ensure_ca_cert_exists(pub_storage, &sk, subject, tls_wildcard).await?;
    ensure_published_verification_material(pub_storage, &sk)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to store scheme verification material for party {party_id}: {e}"
            )
        })?;
    Ok(true)
}

/// Generates stores CA certificates that are used to issue ephemeral mTLS
/// certificates in the enclave.
///
/// The certificate is stored at the fixed [`SIGNING_KEY_ID`] handle, beside the
/// signing key that signs it.
async fn ensure_ca_cert_exists<PubS: Storage>(
    pub_storage: &mut PubS,
    sk: &PrivateSigKey,
    subject: String,
    tls_wildcard: bool,
) -> anyhow::Result<()> {
    let req_id = &*SIGNING_KEY_ID;
    // self-sign a CA certificate with the private signing key
    let sk_der = {
        // Will be fixed as part of [#2781](https://github.com/zama-ai/kms-internal/issues/2781).
        #[expect(deprecated)]
        let ecdsa_sk = sk.sk();
        ecdsa_sk.to_pkcs8_der()?
    };
    let ca_keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &sk_der.as_bytes().into(),
        &rcgen::PKCS_ECDSA_P256K1_SHA256,
    )?;
    let (ca_cert_ki, ca_cert, _ca_params) =
        threshold_networking::tls_certs::create_selfsigned_cert_from_keypair(
            subject.as_str(),
            tls_wildcard,
            true,
            &ca_keypair,
        )?;

    // Store self-signed CA certificate
    store_text_at_request_id(
        pub_storage,
        req_id,
        &ca_cert.pem(),
        &PubDataType::CACert.to_string(),
    )
    .await
    .map_err(|store_err| {
        anyhow::anyhow!("Failed to store CA certificate for party {subject}: {store_err}")
    })?;
    tracing::info!(
        "Successfully stored CA certificate {} under the handle {} in storage \"{}\"",
        ca_cert_ki,
        req_id,
        pub_storage.info()
    );

    Ok(())
}

/// Generates and stores threshold FHE key shares and metadata.
///
/// Manages the complete threshold FHE key lifecycle:
/// 1. Validates input parameters and storage consistency
/// 2. Checks for existing keys
/// 3. Generates key shares with the given threshold parameters
/// 4. Computes and stores metadata for each party
/// 5. Distributes keys to all parties
///
/// # Returns
/// - `true` if new keys were generated and distributed
/// - `false` if keys already existed or an error occurred
///
/// # Panics
/// - If storage access fails
/// - If threshold parameters are invalid
#[cfg(any(test, feature = "testing"))]
pub async fn ensure_threshold_keys_exist<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    dkg_params: DKGParams,
    key_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    // Validate input parameters
    if pub_storages.len() != priv_storages.len() {
        tracing::error!(
            "Number of public storages ({}) and private storages ({}) must be equal",
            pub_storages.len(),
            priv_storages.len()
        );
        return false;
    }

    let amount_parties = pub_storages.len();
    if amount_parties == 0 {
        tracing::error!("Cannot generate threshold keys with zero parties");
        return false;
    }

    // Compute threshold < amount_parties/3
    let threshold = max_threshold(amount_parties);

    // Check if PUBLIC data already exists for all parties. If so, skip entirely.
    // See comment in ensure_central_keys_exist for why we only check PUB.
    let pub_type = PubDataType::CompressedXofKeySet.to_string();
    let legacy_pub_types = [
        PubDataType::CompressedXofKeySet.to_string(),
        PubDataType::PublicKey.to_string(),
        PubDataType::ServerKey.to_string(),
    ];

    let mut all_data_exists = true;
    for pub_storage in pub_storages.iter() {
        all_data_exists &= data_exists(pub_storage, key_id, &pub_type)
            .await
            .unwrap_or(false);
    }
    if all_data_exists {
        tracing::info!("Threshold FHE keys exists, skipping generation");
        return false;
    }
    // Purge obsolete data
    for (pub_storage, priv_storage) in pub_storages.iter_mut().zip_eq(priv_storages.iter_mut()) {
        use crate::vault::storage::delete_at_request_and_epoch_id;

        for existing_pub_type in &legacy_pub_types {
            let _ = delete_at_request_id(pub_storage, key_id, existing_pub_type).await;
        }
        let _ = delete_at_request_and_epoch_id(
            priv_storage,
            key_id,
            epoch_id,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await;
    }

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    // Collect signing keys from all private storages with proper error handling
    let mut signing_keys = Vec::new();
    for (i, cur_storage) in priv_storages.iter().enumerate() {
        match get_core_signing_key(cur_storage).await {
            Ok(key) => signing_keys.push(key),
            Err(e) => {
                tracing::error!("Failed to get signing key for party {}: {}", i + 1, e);
                return false; // Cannot proceed without signing keys
            }
        }
    }

    // Generate compressed key set and shares
    let (keyset, compressed_keyset) = match gen_key_set(dkg_params, key_id.into(), &mut rng) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate compressed key set: {}", e);
            return false;
        }
    };

    // Generate key shares with error handling
    let key_shares = match keygen_all_party_shares_from_client_key(
        &keyset.client_key,
        dkg_params.classic_pbs(),
        &mut rng,
        amount_parties,
        threshold,
    ) {
        Ok(shares) => shares,
        Err(e) => {
            tracing::error!("Failed to generate key shares: {}", e);
            return false;
        }
    };

    // Hash the compressed keyset once; reuse per party.
    let compressed_digest = match hash_versioned(&DSEP_PUBDATA_KEY, &compressed_keyset) {
        Ok(digest) => digest,
        Err(e) => {
            tracing::error!("Failed to hash compressed keyset: {}", e);
            return false;
        }
    };

    // Derive the CompactPublicKey from the compressed keyset once; store and sign it
    // along with the compressed keyset for each party.
    let compact_public_key = compressed_keyset.decompress().into_raw_parts().0;

    // Hash the compact public key once; reuse per party.
    let public_key_digest = match hash_versioned(&DSEP_PUBDATA_KEY, &compact_public_key) {
        Ok(digest) => digest,
        Err(e) => {
            tracing::error!("Failed to hash compact public key: {}", e);
            return false;
        }
    };

    // Wrap the compressed keyset, public key, and per-party shares once; futures hold cheap Arc clones.
    let compressed_keyset = Arc::new(compressed_keyset);
    let compact_public_key = Arc::new(compact_public_key);
    let key_shares: Vec<_> = key_shares.into_iter().map(Arc::new).collect();

    let domain = dummy_domain();
    let store_futs = pub_storages
        .iter_mut()
        .zip(priv_storages.iter_mut())
        .zip(signing_keys.iter())
        .zip(key_shares)
        .enumerate()
        .map(|(idx, (((pub_s, priv_s), sk), share))| {
            let party = idx + 1;
            let compressed_digest = compressed_digest.clone();
            let public_key_digest = public_key_digest.clone();
            let compressed_keyset = compressed_keyset.clone();
            let compact_public_key = compact_public_key.clone();
            let domain = &domain;

            async move {
                let info = match compute_info_compressed_keygen_from_digests(
                    sk,
                    &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
                    &INSECURE_PREPROCESSING_ID,
                    key_id,
                    compressed_digest,
                    public_key_digest,
                    domain,
                    vec![],
                ) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::error!("Failed to compute key info for party {}: {}", party, e);
                        return;
                    }
                };
                let threshold_fhe_keys = ThresholdFheKeys::new(
                    share,
                    PublicKeyMaterial::Compressed {
                        keyset: compressed_keyset.clone(),
                    },
                    info,
                );

                tracing::info!("Storing compressed keyset for party {}", party);
                if let Err(store_err) = store_versioned_at_request_id(
                    pub_s,
                    key_id,
                    &*compressed_keyset,
                    &PubDataType::CompressedXofKeySet.to_string(),
                )
                .await
                {
                    tracing::error!(
                        "Failed to store compressed keyset for party {}: {}",
                        party,
                        store_err
                    );
                    return;
                }
                log_storage_success(key_id, pub_s.info(), "compressed keyset", true, true);

                // Store the compact public key alongside the compressed keyset
                if let Err(store_err) = store_versioned_at_request_id(
                    pub_s,
                    key_id,
                    &*compact_public_key,
                    &PubDataType::PublicKey.to_string(),
                )
                .await
                {
                    tracing::error!(
                        "Failed to store public key for party {}: {}",
                        party,
                        store_err
                    );
                    return;
                }
                log_storage_success(key_id, pub_s.info(), "public key", true, true);

                if let Err(store_err) = store_versioned_at_request_and_epoch_id(
                    priv_s,
                    key_id,
                    epoch_id,
                    &threshold_fhe_keys,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await
                {
                    tracing::error!(
                        "Failed to store private key data for party {}: {}",
                        party,
                        store_err
                    );
                    return;
                }
                log_storage_success(key_id, priv_s.info(), "key data", false, true);
            }
        });

    future::join_all(store_futs).await;
    true
}

/// Generates and stores a threshold CRS with metadata.
///
/// Implements the complete threshold CRS lifecycle:
/// 1. Validates storage consistency
/// 2. Checks for existing CRS
/// 3. Collects signing keys from all parties
/// 4. Generates centralized parameters with proper security
/// 5. Distributes CRS to all parties with signatures
///
/// # Returns
/// - `true` if new CRS was generated and distributed
/// - `false` if CRS already existed
///
/// # Panics
/// - If storage validation fails (inconsistent counts)
/// - If signing key collection fails
/// - If parameter generation fails
/// - If CRS distribution fails
#[cfg(any(test, feature = "testing"))]
pub async fn ensure_threshold_crs_exists<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    dkg_params: DKGParams,
    crs_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    if pub_storages.len() != priv_storages.len() {
        panic!("Number of public storages and private storages must be equal");
    }

    let amount_parties = pub_storages.len();

    // Check if the all parties have the CRS. If so, we can stop, otherwise we need to generate it.
    // PANICS: If storage access fails or if no storage is available
    let mut all_data_exists = true;
    for (pub_storage, priv_storage) in pub_storages.iter().zip_eq(priv_storages.iter()) {
        match check_data_exists_at_epoch(
            pub_storage,
            priv_storage,
            crs_id,
            epoch_id,
            &PubDataType::CRS,
            &PrivDataType::CrsInfo,
        )
        .await
        {
            Ok(true) => continue,
            Ok(false) => {
                tracing::info!("CRS does not exist, proceeding with generation.");
                all_data_exists = false;
                break;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to check if threshold CRS exists, proceeding with generation anyway: {e}"
                );
                all_data_exists = false;
                break;
            }
        }
    }
    if all_data_exists {
        tracing::info!("Threshold CRS exist, skipping generation");
        return false;
    }

    // Collect signing keys from all private storages
    // PANICS: If any signing key cannot be retrieved - critical for security
    let signing_keys: Vec<_> = future::join_all(
        priv_storages
            .iter()
            .map(|storage| get_core_signing_key(storage)),
    )
    .await
    .into_iter()
    .collect::<Result<_, _>>()
    .unwrap_or_else(|e| panic!("Failed to get signing key: {e}"));

    // Calculate max_num_bits based on DKG parameters
    // PANICS: If parameters are invalid and yield zero bits (security critical)
    let max_num_bits = calculate_max_num_bits(&dkg_params);
    if max_num_bits == 0 {
        panic!("Invalid max_num_bits calculated from DKG parameters");
    }

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    // Generate the public parameters - foundation for the entire cryptographic system
    // PANICS: If parameter generation fails - cannot proceed with insecure parameters
    let pke_params = dkg_params.compact_pk_enc_params();

    // Any sid will work for testing
    let sid = SessionId::from(0u128);
    let internal_pp =
        public_parameters_by_trusted_setup(&pke_params, Some(max_num_bits), sid, &mut rng)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to make centralized public parameters (max_bits: {max_num_bits}): {e}"
                );
            });

    // Convert internal parameters to zero-knowledge proof compatible format
    // PANICS: If conversion fails - cryptographic integrity would be compromised
    let pp = internal_pp
        .try_into_tfhe_zk_pok_pp(&pke_params, sid)
        .unwrap_or_else(|e| {
            panic!("Failed to convert internal_pp to tfhe_zk_pok_pp: {e}");
        });

    // Hash pp once; reused per party.
    let crs_digest = hash_versioned(&DSEP_PUBDATA_CRS, &pp)
        .expect("serializing and hashing a CompactPkCrs works");
    let crs_max_num_bits = max_num_bits_from_crs(&pp);

    // Store the CRS for each party. Per-party signing + writes run concurrently.
    let domain = dummy_domain();
    let pp_ref = &pp;
    let store_futs = pub_storages
        .iter_mut()
        .zip_eq(priv_storages.iter_mut().zip_eq(signing_keys.iter()))
        .map(|(cur_pub, (cur_priv, cur_sk))| {
            let crs_digest = crs_digest.clone();
            let domain = &domain;
            async move {
                // PANICS: If signature generation fails - would compromise security model
                let crs_info = compute_info_crs_from_digest(
                    cur_sk,
                    &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
                    crs_id,
                    crs_digest,
                    crs_max_num_bits,
                    domain,
                    vec![],
                )
                .unwrap_or_else(|e| panic!("Failed to compute CRS info for party: {e}"));

                // PANICS: If storage fails - system would be in inconsistent state
                store_versioned_at_request_and_epoch_id::<PrivS, CrsGenMetadata>(
                    cur_priv,
                    crs_id,
                    epoch_id,
                    &crs_info,
                    &PrivDataType::CrsInfo.to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("Failed to store private CRS info for party: {e}"));
                log_storage_success(crs_id, cur_priv.info(), "CRS data", false, true);

                // PANICS: If storage fails - system would be unable to perform cryptographic operations
                store_versioned_at_request_id::<PubS, tfhe::zk::CompactPkeCrs>(
                    cur_pub,
                    crs_id,
                    pp_ref,
                    &PubDataType::CRS.to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("Failed to store public CRS for party: {e}"));
                log_storage_success(crs_id, cur_pub.info(), "CRS data", true, true);
            }
        });

    future::join_all(store_futs).await;
    true
}

/// Calculates the maximum secure threshold for a given number of parties.
///
/// Uses the formula: ⌈n/3⌉ - 1, which ensures security in the presence of malicious parties.
///
/// # Arguments
/// * `amount_parties` - The total number of parties in the threshold system
///
/// # Returns
/// The maximum secure threshold value
pub fn max_threshold(amount_parties: usize) -> usize {
    usize::div_ceil(amount_parties, 3) - 1
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_VERF_MATERIAL_TYPES, LEGACY_VERF_MATERIAL_TYPES,
        delete_scheme_verification_material, ensure_central_server_signing_keys_exist,
        ensure_no_scheme_verification_material, ensure_published_verification_material,
        ensure_threshold_server_signing_key_exists,
    };
    use crate::consts::{SIGNING_KEY_ID, signing_material_id};
    use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey, gen_sig_keys};
    use crate::cryptography::signing::seed::RootSigningSeed;
    use crate::cryptography::signing::{HasSigningScheme, SigningSchemeType, unified_verify};
    use crate::util::key_setup::{all_verf_material_slots, non_legacy_verf_material_slots};
    use crate::vault::storage::crypto_material::{
        get_core_root_signing_seed, get_core_signing_key, read_verification_key_at,
        store_verification_key_at,
    };
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::{
        StorageReader, delete_at_request_id, read_text_at_request_id, store_text_at_request_id,
        store_versioned_at_request_id,
    };
    use crate::{
        consts::DEFAULT_PARAM, dummy_domain, engine::centralized::central_kms::gen_centralized_crs,
    };
    use aes_prng::AesRng;
    use hashing::DomainSep;
    use kms_grpc::RequestId;
    use kms_grpc::rpc_types::{PrivDataType, PubDataType};
    use rand::SeedableRng;
    use std::collections::HashSet;
    use strum::IntoEnumIterator;
    use threshold_execution::zk::ceremony::max_num_bits_from_crs;

    const DSEP: &DomainSep = b"SEEDKGEN";

    #[test]
    fn test_max_num_bits() {
        let mut rng = AesRng::seed_from_u64(123);
        let req_id = RequestId::new_random(&mut rng);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let params = &DEFAULT_PARAM;
        let eip712_domain = dummy_domain();
        for max_num_bits in [64, 128, 256, 1024, 2048] {
            let (crs, _) = gen_centralized_crs(
                &sk,
                &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
                params,
                Some(max_num_bits),
                &eip712_domain,
                vec![],
                &req_id,
                &mut rng,
            )
            .unwrap();
            assert_eq!(max_num_bits as usize, max_num_bits_from_crs(&crs));
        }
    }

    fn seeded_identity(rng: &mut AesRng) -> PrivateSigKey {
        let (_pk, sk) = gen_sig_keys(rng);
        sk.with_root_seed(RootSigningSeed::random(rng))
    }

    /// Asserts every scheme's canonical verification key and address, ECDSA's
    /// included, match `sk`.
    async fn assert_scheme_material_matches<PubS: StorageReader>(
        pub_storage: &PubS,
        sk: &PrivateSigKey,
    ) {
        let addr_type = PubDataType::TypedVerfAddress.to_string();
        for scheme in SigningSchemeType::iter() {
            let id = signing_material_id(scheme);
            let expected = sk.unified_verifying_key(scheme).unwrap();

            let stored_vk = read_verification_key_at(
                pub_storage,
                &signing_material_id(scheme),
                PubDataType::TypedVerfKey,
                scheme,
            )
            .await
            .unwrap();
            assert_eq!(stored_vk, expected, "{scheme:?} verf key mismatch");

            let stored_addr = read_text_at_request_id(pub_storage, &id, &addr_type)
                .await
                .unwrap();
            assert_eq!(
                stored_addr,
                expected.address_text(),
                "{scheme:?} digest mismatch"
            );
            assert!(
                stored_addr.starts_with("0x"),
                "{scheme:?} digest is not 0x-prefixed"
            );
        }
    }

    /// Writes every scheme's verification key and digest, ECDSA's included, plus
    /// the deprecated ECDSA-only pair — and the deprecated pair holds byte-for-byte
    /// what ECDSA's canonical pair holds, which is what lets one code path serve
    /// both.
    #[tokio::test]
    async fn writes_material_for_every_scheme() {
        let mut rng = AesRng::seed_from_u64(7);
        let sk = seeded_identity(&mut rng);
        let mut pub_storage = RamStorage::new();

        ensure_published_verification_material(&mut pub_storage, &sk)
            .await
            .unwrap();

        assert_scheme_material_matches(&pub_storage, &sk).await;

        // ECDSA's entry is the scheme-tagged key, and its text is the very same
        // Ethereum address the deprecated location holds.
        let ecdsa_id = signing_material_id(SigningSchemeType::Ecdsa256k1);
        let stored_ecdsa: PublicSigKey = pub_storage
            .read_data(&ecdsa_id, &PubDataType::TypedVerfKey.to_string())
            .await
            .unwrap();
        assert_eq!(stored_ecdsa, sk.verf_key());
        assert_eq!(
            read_text_at_request_id(
                &pub_storage,
                &ecdsa_id,
                &PubDataType::TypedVerfAddress.to_string()
            )
            .await
            .unwrap(),
            sk.verf_key().address().to_string()
        );

        // The deprecated ECDSA-only pair is written too, and is byte-for-byte the
        // canonical ECDSA pair under a different handle and folder.
        for (legacy, canonical) in LEGACY_VERF_MATERIAL_TYPES
            .iter()
            .zip(CURRENT_VERF_MATERIAL_TYPES.iter())
        {
            assert_eq!(
                pub_storage
                    .load_bytes(&SIGNING_KEY_ID, &legacy.to_string())
                    .await
                    .unwrap(),
                pub_storage
                    .load_bytes(&ecdsa_id, &canonical.to_string())
                    .await
                    .unwrap(),
                "{legacy} and {canonical} disagree about the ECDSA identity"
            );
        }
    }

    /// Writing is idempotent, leftovers are detected, and deleting them clears the
    /// way for a different signing key — the sequence `kms-gen-keys --overwrite`
    /// relies on.
    #[tokio::test]
    async fn delete_allows_regenerating_from_a_new_signing_key() {
        let mut rng = AesRng::seed_from_u64(11);
        let sk_old = seeded_identity(&mut rng);
        let sk_new = seeded_identity(&mut rng);
        let mut pub_storage = RamStorage::new();

        // Empty storage: nothing to detect, and deleting is a no-op.
        ensure_no_scheme_verification_material(&pub_storage)
            .await
            .unwrap();
        delete_scheme_verification_material(&mut pub_storage)
            .await
            .unwrap();

        ensure_published_verification_material(&mut pub_storage, &sk_old)
            .await
            .unwrap();
        // Re-running against the material it just wrote changes nothing.
        ensure_published_verification_material(&mut pub_storage, &sk_old)
            .await
            .unwrap();
        assert_scheme_material_matches(&pub_storage, &sk_old).await;

        // The leftovers are what stops key generation from running over them.
        assert!(
            ensure_no_scheme_verification_material(&pub_storage)
                .await
                .is_err()
        );

        delete_scheme_verification_material(&mut pub_storage)
            .await
            .unwrap();
        ensure_no_scheme_verification_material(&pub_storage)
            .await
            .unwrap();

        // The deprecated pair still describes the old key, and a different key must
        // not be published beside it. `kms-gen-keys --overwrite` deletes it together
        // with the signing key for exactly this reason.
        assert!(
            ensure_published_verification_material(&mut pub_storage, &sk_new)
                .await
                .is_err(),
            "a new identity was published over the old deprecated ECDSA material"
        );
        for data_type in LEGACY_VERF_MATERIAL_TYPES.map(|t| t.to_string()) {
            delete_at_request_id(&mut pub_storage, &SIGNING_KEY_ID, &data_type)
                .await
                .unwrap();
        }

        ensure_published_verification_material(&mut pub_storage, &sk_new)
            .await
            .unwrap();
        assert_scheme_material_matches(&pub_storage, &sk_new).await;
    }

    /// The canonical folders hold exactly one handle per scheme, and each object is
    /// that scheme's own native verification key type.
    #[tokio::test]
    async fn scheme_folders_hold_one_native_object_per_scheme() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();

        // The deprecated ECDSA-only folders hold the primary identity and nothing
        // else: a bare PublicSigKey, still readable as such.
        for data_type in LEGACY_VERF_MATERIAL_TYPES {
            let ids = pub_storage
                .all_data_ids(&data_type.to_string())
                .await
                .unwrap();
            assert_eq!(
                ids,
                HashSet::from([*SIGNING_KEY_ID]),
                "{data_type} holds handles other than the ECDSA identity"
            );
        }
        let legacy_ecdsa_vk: PublicSigKey = pub_storage
            .read_data(&SIGNING_KEY_ID, &PubDataType::VerfKey.to_string())
            .await
            .unwrap();

        // Both canonical folders hold exactly one handle per scheme.
        let verf_key_type = PubDataType::TypedVerfKey.to_string();
        let addr_type = PubDataType::TypedVerfAddress.to_string();
        let expected_ids = SigningSchemeType::iter()
            .map(signing_material_id)
            .collect::<HashSet<RequestId>>();
        assert_eq!(
            pub_storage.all_data_ids(&verf_key_type).await.unwrap(),
            expected_ids,
            "the verification keys are not exactly one per scheme"
        );
        assert_eq!(
            pub_storage.all_data_ids(&addr_type).await.unwrap(),
            expected_ids,
            "the digests are not exactly one per scheme"
        );

        let sk = get_core_signing_key(&priv_storage).await.unwrap();
        assert_scheme_material_matches(&pub_storage, &sk).await;

        // Both locations describe the same ECDSA identity, and the canonical one holds
        // the bare `PublicSigKey` the deprecated one holds — not a tagged wrapper.
        assert_eq!(legacy_ecdsa_vk, sk.verf_key());
        let canonical_ecdsa: PublicSigKey = pub_storage
            .read_data(
                &signing_material_id(SigningSchemeType::Ecdsa256k1),
                &verf_key_type,
            )
            .await
            .unwrap();
        assert_eq!(canonical_ecdsa, legacy_ecdsa_vk);
    }

    /// Fails loudly if the stored *deprecated* ECDSA verification key does not match
    /// the signing key it is asked to derive from.
    #[tokio::test]
    async fn rejects_mismatched_legacy_ecdsa_verf_key() {
        let mut rng = AesRng::seed_from_u64(10);
        let sk_a = seeded_identity(&mut rng);
        let (pk_b, _sk_b) = gen_sig_keys(&mut rng);
        let mut pub_storage = RamStorage::new();

        // Publish a verification key belonging to a *different* signing key.
        store_versioned_at_request_id(
            &mut pub_storage,
            &SIGNING_KEY_ID,
            &pk_b,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();

        assert!(
            ensure_published_verification_material(&mut pub_storage, &sk_a)
                .await
                .is_err()
        );
    }

    /// Fails loudly for *every* scheme, not just ECDSA: a verification key left
    /// behind by a previous signing key is never silently kept, wherever it sits.
    #[tokio::test]
    async fn rejects_mismatched_verf_key_of_any_scheme() {
        for scheme in SigningSchemeType::iter() {
            let mut rng = AesRng::seed_from_u64(12);
            let sk_a = seeded_identity(&mut rng);
            let sk_b = seeded_identity(&mut rng);
            let mut pub_storage = RamStorage::new();

            let vk_b = &sk_b.unified_verifying_key(scheme).unwrap();
            // Publish this scheme's key as derived from a *different* signing key.
            store_verification_key_at(
                &mut pub_storage,
                &signing_material_id(vk_b.signing_scheme_type()),
                PubDataType::TypedVerfKey,
                vk_b,
            )
            .await
            .unwrap();

            assert!(
                ensure_published_verification_material(&mut pub_storage, &sk_a)
                    .await
                    .is_err(),
                "a stale {scheme} verification key was accepted"
            );
        }
    }

    /// Fails loudly for *every* scheme, not just ECDSA: a verification address left
    /// behind by a previous signing key is never silently kept, wherever it sits.
    #[tokio::test]
    async fn rejects_mismatched_digest_of_any_scheme() {
        let addr_type = PubDataType::TypedVerfAddress.to_string();
        let mut rng = AesRng::seed_from_u64(13);
        for scheme in SigningSchemeType::iter() {
            let sk = seeded_identity(&mut rng);
            let mut pub_storage = RamStorage::new();

            // The digest of the right key, in the pre-0.16 encoding: no `0x` prefix.
            let expected = sk.unified_verifying_key(scheme).unwrap();
            store_text_at_request_id(
                &mut pub_storage,
                &signing_material_id(scheme),
                &hex::encode(expected.digest()),
                &addr_type,
            )
            .await
            .unwrap();

            assert!(
                ensure_published_verification_material(&mut pub_storage, &sk)
                    .await
                    .is_err(),
                "a {scheme} digest in the old encoding was accepted"
            );
        }
    }

    #[test]
    fn scheme_handles_are_pinned_and_distinct() {
        use crate::engine::base::derive_request_id;

        // ECDSA stays at the historical handle for backwards compatibility.
        assert_eq!(
            signing_material_id(SigningSchemeType::Ecdsa256k1),
            *SIGNING_KEY_ID
        );
        for (scheme, expected_seed) in [
            (SigningSchemeType::Ed25519, "SIGNING_KEY_ID_Ed25519"),
            (SigningSchemeType::MlDsa44, "SIGNING_KEY_ID_MlDsa44"),
            (SigningSchemeType::MlDsa65, "SIGNING_KEY_ID_MlDsa65"),
            (SigningSchemeType::MlDsa87, "SIGNING_KEY_ID_MlDsa87"),
        ] {
            assert_eq!(
                signing_material_id(scheme),
                derive_request_id(expected_seed).unwrap(),
                "the storage handle of {scheme} moved"
            );
        }

        // No two schemes may share a handle, or one would overwrite the other.
        let ids: HashSet<RequestId> = SigningSchemeType::iter().map(signing_material_id).collect();
        assert_eq!(ids.len(), SigningSchemeType::iter().count());
    }

    async fn persisted_signing_key_bytes<S: StorageReader>(priv_storage: &S) -> Vec<u8> {
        priv_storage
            .load_bytes(&SIGNING_KEY_ID, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap()
    }

    async fn seed_exists<S: StorageReader>(priv_storage: &S) -> bool {
        priv_storage
            .data_exists(&SIGNING_KEY_ID, &PrivDataType::SigningSeed.to_string())
            .await
            .unwrap()
    }

    /// Whether public storage holds any non-ECDSA verification material.
    async fn non_ecdsa_material_exists<S: StorageReader>(pub_storage: &S) -> bool {
        for scheme in SigningSchemeType::iter().filter(|s| *s != SigningSchemeType::Ecdsa256k1) {
            for data_type in CURRENT_VERF_MATERIAL_TYPES.map(|t| t.to_string()) {
                if pub_storage
                    .data_exists(&signing_material_id(scheme), &data_type)
                    .await
                    .unwrap()
                {
                    return true;
                }
            }
        }
        false
    }

    /// The end-to-end tie-down between the runtime identity and what storage
    /// publishes.
    #[tokio::test]
    async fn published_material_verifies_what_the_runtime_identity_signs() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        assert!(
            ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
                .await
                .unwrap()
        );

        let sk = get_core_signing_key(&priv_storage).await.unwrap();
        assert!(sk.has_root_seed(), "the loaded identity lost its root seed");

        let msg = b"signed by the identity the server boots with";
        for scheme in SigningSchemeType::iter() {
            let sig = sk.unified_sign_with(scheme, DSEP, msg).unwrap();
            let published = read_verification_key_at(
                &pub_storage,
                &signing_material_id(scheme),
                PubDataType::TypedVerfKey,
                scheme,
            )
            .await
            .unwrap();
            unified_verify(DSEP, msg, &sig, &published).unwrap_or_else(|e| {
                panic!("{scheme} signature does not verify against the published key: {e}")
            });
        }
    }

    /// A fresh node roots its whole identity in the seed.
    #[tokio::test]
    async fn fresh_node_derives_its_ecdsa_key_from_the_seed() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        assert!(
            ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
                .await
                .unwrap()
        );

        let seed = get_core_root_signing_seed(&priv_storage)
            .await
            .unwrap()
            .expect("a fresh node must have a root seed");
        let sk = get_core_signing_key(&priv_storage).await.unwrap();
        assert_eq!(
            sk.verf_key(),
            seed.derive_ecdsa_signing_key().unwrap().verf_key(),
            "the persisted ECDSA key is not the one the seed derives"
        );

        // The deprecated ECDSA location agrees with it too.
        let published_address = crate::vault::storage::read_text_at_request_id(
            &pub_storage,
            &SIGNING_KEY_ID,
            &PubDataType::VerfAddress.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(published_address, sk.verf_key().address().to_string());

        // Rerunning is a no-op: no new key, no new seed.
        let key_before = persisted_signing_key_bytes(&priv_storage).await;
        assert!(
            !ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
                .await
                .unwrap()
        );
        assert_eq!(persisted_signing_key_bytes(&priv_storage).await, key_before);
        assert_eq!(
            get_core_root_signing_seed(&priv_storage).await.unwrap(),
            Some(seed)
        );
    }

    /// A per-scheme object lost from public storage — a partial purge, or a
    /// snapshot restored from before a scheme existed — is rewritten on the next
    /// run, identical to what it was, without touching any private key.
    #[tokio::test]
    async fn a_deleted_per_scheme_object_is_backfilled_on_rerun() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();
        let key_before = persisted_signing_key_bytes(&priv_storage).await;

        // Each scheme in turn, and both of its objects: whichever one is missing
        // has to come back.
        for scheme in SigningSchemeType::iter() {
            for data_type in CURRENT_VERF_MATERIAL_TYPES.map(|t| t.to_string()) {
                let req_id = signing_material_id(scheme);
                let expected = pub_storage.load_bytes(&req_id, &data_type).await.unwrap();
                delete_at_request_id(&mut pub_storage, &req_id, &data_type)
                    .await
                    .unwrap();
                assert!(!pub_storage.data_exists(&req_id, &data_type).await.unwrap());

                assert!(
                    !ensure_central_server_signing_keys_exist(
                        &mut pub_storage,
                        &mut priv_storage,
                        true
                    )
                    .await
                    .unwrap(),
                    "backfilling must not count as generating a new identity"
                );

                assert_eq!(
                    pub_storage.load_bytes(&req_id, &data_type).await.unwrap(),
                    expected,
                    "{scheme} {data_type} was not restored byte-for-byte"
                );
            }
        }

        // Nothing private moved while all that was going on.
        assert_eq!(persisted_signing_key_bytes(&priv_storage).await, key_before);
    }

    /// An upgraded node keeps its on-chain ECDSA identity byte-for-byte and only
    /// gains a seed plus the non-ECDSA material derived from it.
    #[tokio::test]
    async fn upgraded_node_keeps_its_ecdsa_key_and_gains_a_seed() {
        let mut rng = AesRng::seed_from_u64(21);
        let (_pk, legacy_sk) = gen_sig_keys(&mut rng);
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        // A pre-multi-scheme storage: an ECDSA signing key and nothing else.
        store_versioned_at_request_id(
            &mut priv_storage,
            &SIGNING_KEY_ID,
            &legacy_sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        let key_before = persisted_signing_key_bytes(&priv_storage).await;
        assert!(!seed_exists(&priv_storage).await);

        assert!(
            !ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
                .await
                .unwrap(),
            "an existing signing key must not count as newly generated"
        );

        assert_eq!(
            persisted_signing_key_bytes(&priv_storage).await,
            key_before,
            "the ECDSA identity of an upgraded node moved"
        );
        let seed = get_core_root_signing_seed(&priv_storage)
            .await
            .unwrap()
            .expect("the upgrade must add a root seed");
        assert!(non_ecdsa_material_exists(&pub_storage).await);

        // Published material describes the persisted key for ECDSA and the
        // seed-derived keys for everything else.
        let sk = get_core_signing_key(&priv_storage).await.unwrap();
        for scheme in SigningSchemeType::iter() {
            assert_eq!(
                read_verification_key_at(
                    &pub_storage,
                    &signing_material_id(scheme),
                    PubDataType::TypedVerfKey,
                    scheme
                )
                .await
                .unwrap(),
                sk.unified_verifying_key(scheme).unwrap(),
                "{scheme} material does not match the loaded identity"
            );
        }
        assert_eq!(
            read_verification_key_at(
                &pub_storage,
                &signing_material_id(SigningSchemeType::Ecdsa256k1),
                PubDataType::TypedVerfKey,
                SigningSchemeType::Ecdsa256k1
            )
            .await
            .unwrap(),
            legacy_sk
                .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
                .unwrap(),
        );
        // The transition invariant: the post-rotation ECDSA key stays unpublished.
        assert_ne!(
            seed.derive_ecdsa_signing_key().unwrap().verf_key(),
            legacy_sk.verf_key(),
            "the seed happened to derive the legacy key, so this asserts nothing"
        );
    }

    /// A seed is never re-minted once material derived from one has been published.
    #[tokio::test]
    async fn seed_is_not_reminted_behind_published_material() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();

        // Lose only the seed — the signing key and all published material stay.
        delete_at_request_id(
            &mut priv_storage,
            &SIGNING_KEY_ID,
            &PrivDataType::SigningSeed.to_string(),
        )
        .await
        .unwrap();

        assert!(
            ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
                .await
                .is_err(),
            "a missing seed behind published material must be an error, not a regeneration"
        );
        assert!(
            !seed_exists(&priv_storage).await,
            "a replacement seed was written anyway"
        );
    }

    /// A seed with no signing key beside it is an interrupted run or a partial wipe,
    /// not a state to generate into.
    #[tokio::test]
    async fn seed_without_a_signing_key_is_rejected() {
        let mut rng = AesRng::seed_from_u64(22);
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        store_versioned_at_request_id(
            &mut priv_storage,
            &SIGNING_KEY_ID,
            &RootSigningSeed::random(&mut rng),
            &PrivDataType::SigningSeed.to_string(),
        )
        .await
        .unwrap();

        assert!(
            ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
                .await
                .is_err()
        );
        assert!(
            !priv_storage
                .data_exists(&SIGNING_KEY_ID, &PrivDataType::SigningKey.to_string())
                .await
                .unwrap()
        );
    }

    /// Deleting the seed together with the signing key and the published material —
    /// what `kms-gen-keys --overwrite` does — leaves a storage a fresh identity can
    /// be generated into.
    #[tokio::test]
    async fn overwrite_sequence_allows_a_new_identity() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();
        let first_key = persisted_signing_key_bytes(&priv_storage).await;
        let first_seed = get_core_root_signing_seed(&priv_storage)
            .await
            .unwrap()
            .expect("the first run must write a root seed");

        super::delete_published_verification_material(&mut pub_storage)
            .await
            .unwrap();
        for data_type in [PrivDataType::SigningKey, PrivDataType::SigningSeed] {
            delete_at_request_id(&mut priv_storage, &SIGNING_KEY_ID, &data_type.to_string())
                .await
                .unwrap();
        }

        // Regenerate non-deterministically.
        assert!(
            ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, false)
                .await
                .unwrap(),
            "a wiped storage must generate a fresh identity"
        );

        let seed = get_core_root_signing_seed(&priv_storage)
            .await
            .unwrap()
            .expect("regeneration must write a root seed");
        assert_ne!(
            persisted_signing_key_bytes(&priv_storage).await,
            first_key,
            "the ECDSA key survived the overwrite"
        );
        assert_ne!(seed, first_seed, "the root seed survived the overwrite");
        let sk = get_core_signing_key(&priv_storage).await.unwrap();
        assert_eq!(
            sk.verf_key(),
            seed.derive_ecdsa_signing_key().unwrap().verf_key(),
            "the regenerated ECDSA key is not the one the new seed derives"
        );
        for scheme in SigningSchemeType::iter() {
            assert_eq!(
                read_verification_key_at(
                    &pub_storage,
                    &signing_material_id(scheme),
                    PubDataType::TypedVerfKey,
                    scheme
                )
                .await
                .unwrap(),
                sk.unified_verifying_key(scheme).unwrap(),
                "{scheme} material was not republished for the regenerated identity"
            );
        }
    }

    /// The threshold path behaves like the central one, and gives each party its own
    /// independent seed.
    #[tokio::test]
    async fn threshold_parties_get_independent_seeds() {
        let mut seeds = Vec::new();
        for party in [1usize, 2] {
            let mut pub_storage = RamStorage::new();
            let mut priv_storage = RamStorage::new();
            assert!(
                ensure_threshold_server_signing_key_exists(
                    &mut pub_storage,
                    &mut priv_storage,
                    true,
                    std::num::NonZeroUsize::new(party).unwrap(),
                    format!("p{party}"),
                    false,
                )
                .await
                .unwrap()
            );

            let seed = get_core_root_signing_seed(&priv_storage)
                .await
                .unwrap()
                .expect("a fresh threshold party must have a root seed");
            let sk: PrivateSigKey = get_core_signing_key(&priv_storage).await.unwrap();
            assert_eq!(
                sk.verf_key(),
                seed.derive_ecdsa_signing_key().unwrap().verf_key()
            );
            seeds.push(seed);
        }
        assert_ne!(seeds[0], seeds[1], "two parties share a root seed");
    }

    /// What a node generated and what it published agree, so the read-only
    /// validation the server runs at boot passes on a healthy storage.
    #[tokio::test]
    async fn validation_accepts_a_healthy_storage() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();
        let sk = get_core_signing_key(&priv_storage).await.unwrap();

        super::validate_slots(&pub_storage, &sk, all_verf_material_slots())
            .await
            .unwrap();
    }

    /// A node whose seed was swapped out from under its published material is rejected.
    #[tokio::test]
    async fn validation_rejects_material_from_a_different_root() {
        for scheme in SigningSchemeType::iter() {
            let mut rng = AesRng::seed_from_u64(41);
            let mut pub_storage = RamStorage::new();
            let mut priv_storage = RamStorage::new();

            ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
                .await
                .unwrap();
            let sk = get_core_signing_key(&priv_storage).await.unwrap();
            super::validate_slots(&pub_storage, &sk, all_verf_material_slots())
                .await
                .unwrap();

            // Re-root this one scheme's published key onto an unrelated identity,
            // leaving everything else exactly as generated.
            let impostor = seeded_identity(&mut rng);
            let req_id = signing_material_id(scheme);
            let data_type = PubDataType::TypedVerfKey.to_string();
            delete_at_request_id(&mut pub_storage, &req_id, &data_type)
                .await
                .unwrap();
            store_verification_key_at(
                &mut pub_storage,
                &req_id,
                PubDataType::TypedVerfKey,
                &impostor.unified_verifying_key(scheme).unwrap(),
            )
            .await
            .unwrap();

            assert!(
                super::validate_slots(&pub_storage, &sk, all_verf_material_slots())
                    .await
                    .is_err(),
                "a {scheme} verification key from a different root was accepted"
            );
        }
    }

    /// An ECDSA-only node — upgraded from a release that predates the root seed and
    /// not yet through `kms-gen-keys` — validates cleanly.
    #[tokio::test]
    async fn validation_accepts_a_seedless_ecdsa_only_node() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_pk, legacy_sk) = gen_sig_keys(&mut rng);
        let mut pub_storage = RamStorage::new();

        for data_type in LEGACY_VERF_MATERIAL_TYPES {
            let slot_is_key = data_type == PubDataType::VerfKey;
            let vk = legacy_sk
                .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
                .unwrap();
            if slot_is_key {
                store_verification_key_at(&mut pub_storage, &SIGNING_KEY_ID, data_type, &vk)
                    .await
                    .unwrap();
            } else {
                store_text_at_request_id(
                    &mut pub_storage,
                    &SIGNING_KEY_ID,
                    &vk.address_text(),
                    &data_type.to_string(),
                )
                .await
                .unwrap();
            }
        }

        assert!(!legacy_sk.has_root_seed());
        super::validate_slots(&pub_storage, &legacy_sk, all_verf_material_slots())
            .await
            .unwrap();
    }

    /// The lost-seed state: post-quantum material is published, but the node no
    /// longer holds the root that produced it.
    #[tokio::test]
    async fn validation_rejects_published_pq_material_without_a_seed() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();

        // Same ECDSA scalar, seed gone: reading the `SigningKey` object on its own
        // is exactly how a node ends up seedless, since the seed is a separate
        // object that `#[serde(skip)]` keeps out of this one.
        let seedless: PrivateSigKey = priv_storage
            .read_data(&SIGNING_KEY_ID, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
        assert!(!seedless.has_root_seed());

        assert!(
            super::validate_slots(&pub_storage, &seedless, all_verf_material_slots())
                .await
                .is_err(),
            "published post-quantum material with no seed behind it was accepted"
        );
        // Also through the narrower check the server runs at boot, which is where
        // this state has to surface.
        assert!(
            super::validate_slots(&pub_storage, &seedless, non_legacy_verf_material_slots())
                .await
                .is_err(),
            "the boot check accepted published post-quantum material with no seed behind it"
        );
    }

    /// Deletion is the exact inverse of writing, deprecated ECDSA pair included.
    /// When the two disagreed, the leftovers silently blocked the next identity
    /// from being published.
    #[tokio::test]
    async fn deleting_published_material_is_the_inverse_of_writing_it() {
        let mut rng = AesRng::seed_from_u64(44);
        let sk = seeded_identity(&mut rng);
        let mut pub_storage = RamStorage::new();

        ensure_published_verification_material(&mut pub_storage, &sk)
            .await
            .unwrap();
        assert!(
            non_ecdsa_material_exists(&pub_storage).await,
            "nothing was written, so the deletion below would prove nothing"
        );

        super::delete_published_verification_material(&mut pub_storage)
            .await
            .unwrap();

        ensure_no_scheme_verification_material(&pub_storage)
            .await
            .unwrap();
        for data_type in LEGACY_VERF_MATERIAL_TYPES.map(|t| t.to_string()) {
            assert!(
                !pub_storage
                    .data_exists(&SIGNING_KEY_ID, &data_type)
                    .await
                    .unwrap(),
                "the deprecated {data_type} survived the deletion"
            );
        }

        // The point of the mirror: a wiped storage takes a *different* identity
        // without tripping over anything the previous one left behind.
        let other = seeded_identity(&mut rng);
        ensure_published_verification_material(&mut pub_storage, &other)
            .await
            .unwrap();
        assert_scheme_material_matches(&pub_storage, &other).await;
    }
}
