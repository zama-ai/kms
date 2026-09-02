//! Fetching public material from peers and syncing it into this node's public storage at boot.
//!
//! Public storage can lose entries or hold corrupt ones (see
//! [`crate::engine::storage_material_verification`] for how that happens). Every party in an MPC
//! context publishes the same keysets and CRSes, so a node whose own copy is missing or damaged
//! can repair it from a peer's public storage — the peer URLs are recorded in the
//! [`ContextInfo`](crate::engine::context::ContextInfo) entries of private storage.
//!
//! Downloaded bytes are trusted for one reason only: they hash, under the correct domain
//! separator, to a digest taken from this node's own private metadata
//! ([`KeyGenMetadata`] / [`CrsGenMetadata`]), whose signatures boot verification checks
//! independently. A malicious or corrupt peer therefore cannot plant material, only fail to
//! supply it. The flip side is that only digest-validatable material is ever fetched: current
//! keyset metadata (`PublicKey`, `ServerKey`, `CompressedXofKeySet`) and current CRS metadata.
//! Legacy metadata carries no digest, `DecompressionKey` has no private counterpart, and the
//! node-specific types (verification keys and addresses, CA certificates, recovery material)
//! exist per party — a peer holds its own copies, not this node's — so none of those can be
//! repaired from peers.
//!
//! [`sync_public_material_from_peers`] runs during threshold boot, after private metadata
//! validation and before
//! [`verify_storage_material`](crate::engine::storage_material_verification::verify_storage_material):
//! it downloads what is missing, replaces what is digest-mismatched, and then the unchanged
//! read-only verification independently re-checks everything, including what was just written.
//! Centralized nodes do not run it (no peer publishes their material), and recovery mode skips
//! it along with the other startup checks.
//!
//! The peer fetcher itself, [`fetch_verified_public_bytes_from_peers`], is shared with the
//! resharing fallback in [`crate::engine::threshold::service::reshare_utils`].

use crate::engine::base::{CrsGenMetadata, KeyGenMetadata, classify_current_public_material};
use crate::engine::context::NodeInfo;
use crate::engine::material_integrity::verify_public_material_digest_from_bytes;
use crate::vault::storage::{
    Storage, StorageReader, StorageType, StoreWriteOutcome, read_context_at_id,
    s3::{ReadOnlyS3StorageGetter, build_anonymous_s3_client, find_region_from_s3_url, split_url},
    select_data_from_max_epoch,
};
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{ContextId, EpochId, RequestId};
use rand::seq::SliceRandom;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub(crate) const ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS: &str = "Failed to fetch public materials";

/// Build an anonymous read-only client for one peer's public storage.
///
/// A node with an empty storage URL fails here: the default context is written with empty URLs
/// because a node only knows its peers' buckets once a context arrives over gRPC. Callers skip
/// such a peer rather than aborting, so one bad entry never blocks fetching from the others.
async fn peer_public_storage<G, R>(node: &NodeInfo, ro_storage_getter: &G) -> anyhow::Result<R>
where
    G: ReadOnlyS3StorageGetter<R>,
    R: StorageReader,
{
    if node.public_storage_url.is_empty() {
        anyhow::bail!("no public storage URL recorded for this node");
    }
    // The public storage URL consists of the bucket name and the URL,
    // which need to be parsed out separately.
    let (protocol, domain, bucket) = split_url(&node.public_storage_url)?;
    let url = format!("{protocol}{domain}");
    let region = find_region_from_s3_url(&node.public_storage_url)?;

    // This is not an operation that is frequently used, so we can create a new s3 client each time.
    let s3_client = build_anonymous_s3_client(&url, region).await?;
    ro_storage_getter.get_storage(
        s3_client,
        bucket,
        StorageType::PUB,
        node.public_storage_prefix.as_deref(),
    )
}

/// Fetch the raw bytes of the public material stored under `id` from a peer's public storage
/// and verify each entry against its expected digest.
///
/// Peers are tried one at a time in random order (so recovering nodes spread their load instead
/// of all hitting the first-listed party), and the result is the first peer for which *every*
/// requested entry loads and digest-verifies. A peer with an empty or malformed storage URL, an
/// unreachable storage, a missing entry, or a digest mismatch is skipped with a warning; only
/// when every peer has failed does the call error, naming each peer's failure.
///
/// The returned bytes are exactly what the peer stored, so callers can persist them verbatim
/// (keeping the digest valid) or deserialize them.
pub(crate) async fn fetch_verified_public_bytes_from_peers<G, R>(
    mpc_nodes: &[NodeInfo],
    id: &RequestId,
    expected_digests: &BTreeMap<PubDataType, Vec<u8>>,
    ro_storage_getter: &G,
) -> anyhow::Result<BTreeMap<PubDataType, Vec<u8>>>
where
    G: ReadOnlyS3StorageGetter<R>,
    R: StorageReader,
{
    anyhow::ensure!(
        !expected_digests.is_empty(),
        "no expected digests given for id={id}; nothing can be fetched"
    );

    // To simplify the logic it is fine to iterate over ourselves too; our own storage is just
    // one more candidate that may or may not hold valid bytes.
    let mut nodes: Vec<&NodeInfo> = mpc_nodes.iter().collect();
    nodes.shuffle(&mut rand::thread_rng());

    let mut errors = Vec::new();
    'peers: for node in nodes {
        let pub_storage = match peer_public_storage(node, ro_storage_getter).await {
            Ok(storage) => storage,
            Err(e) => {
                let msg = format!(
                    "Cannot access public storage of peer {}: {e:#}",
                    node.party_id
                );
                tracing::warn!(msg);
                errors.push(msg);
                continue;
            }
        };

        let mut verified = BTreeMap::new();
        for (data_type, expected_digest) in expected_digests {
            let bytes = match pub_storage.load_bytes(id, &data_type.to_string()).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    let msg = format!(
                        "{ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS}: {data_type} for id={id} from peer {}: {e:#}",
                        node.party_id
                    );
                    tracing::warn!(msg);
                    errors.push(msg);
                    continue 'peers;
                }
            };
            match verify_public_material_digest_from_bytes(*data_type, &bytes, expected_digest) {
                Ok(()) => {
                    verified.insert(*data_type, bytes);
                }
                Err(e) => {
                    let msg = format!(
                        "Verification failed for {data_type} with id={id} from peer {}: {e:#}",
                        node.party_id
                    );
                    tracing::warn!(msg);
                    errors.push(msg);
                    continue 'peers;
                }
            }
        }
        return Ok(verified);
    }

    anyhow::bail!(
        "{ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS} for id={id} from any of {} peer(s): [{}]",
        mpc_nodes.len(),
        errors.join("; "),
    )
}

/// What [`sync_public_material_from_peers`] did, for the boot log and for tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PublicMaterialSyncReport {
    /// Entries absent from own public storage that were downloaded and stored.
    pub(crate) fetched: Vec<(RequestId, PubDataType)>,
    /// Entries whose local bytes did not hash to their digest and were replaced.
    pub(crate) repaired: Vec<(RequestId, PubDataType)>,
    /// IDs whose metadata is legacy and carries no digest, so they cannot be synced.
    pub(crate) skipped_legacy: BTreeSet<RequestId>,
    /// Number of entries whose local bytes already matched their digest.
    pub(crate) consistent: usize,
}

impl std::fmt::Display for PublicMaterialSyncReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} entry(ies) consistent, {} fetched {:?}, {} repaired {:?}, {} legacy id(s) skipped {:?}",
            self.consistent,
            self.fetched.len(),
            self.fetched,
            self.repaired.len(),
            self.repaired,
            self.skipped_legacy.len(),
            self.skipped_legacy,
        )
    }
}

/// Why one public-storage entry needs to be fetched from peers.
enum OutOfSync {
    /// The entry is absent from own public storage.
    Missing,
    /// The entry exists but its raw bytes do not hash to the digest in private metadata.
    Mismatch,
}

/// Compare one public-storage entry against its expected digest.
///
/// A read failure on an entry that exists propagates as an error: it is a storage fault, not an
/// integrity finding, and repairing over it could destroy good data.
async fn out_of_sync<PubS>(
    public_storage: &PubS,
    id: &RequestId,
    data_type: PubDataType,
    expected_digest: &[u8],
) -> anyhow::Result<Option<OutOfSync>>
where
    PubS: Storage + Send + Sync,
{
    if !public_storage
        .data_exists(id, &data_type.to_string())
        .await?
    {
        return Ok(Some(OutOfSync::Missing));
    }
    let bytes = public_storage
        .load_bytes(id, &data_type.to_string())
        .await?;
    match verify_public_material_digest_from_bytes(data_type, &bytes, expected_digest) {
        Ok(()) => Ok(None),
        Err(e) => {
            tracing::warn!(
                "Public material {data_type} for id={id} does not match the digest in private \
                 metadata ({e:#}); will replace it with verified bytes from a peer"
            );
            Ok(Some(OutOfSync::Mismatch))
        }
    }
}

/// One ID whose public material needs fetching: the epoch that locates its context, and the
/// expected digest plus out-of-sync reason per data type.
struct SyncWorkItem {
    id: RequestId,
    epoch_id: EpochId,
    digests: BTreeMap<PubDataType, Vec<u8>>,
    reasons: BTreeMap<PubDataType, OutOfSync>,
}

/// Bring own public storage in sync with the keyset and CRS digests in private metadata by
/// fetching missing or digest-mismatched entries from the peers of each material's context.
///
/// Metadata for the same ID under several epochs is collapsed to the greatest epoch, consistent
/// with [`select_data_from_max_epoch`]: public objects are not epoched, so one ID has one set of
/// published bytes. That epoch's context (via `epoch_contexts` and the `ContextInfo` in private
/// storage) provides the peer list. Legacy metadata has no digest and is only counted, never
/// fetched — the presence check in boot verification still covers it.
///
/// Every needed entry that cannot be fetched and verified from any peer is an error, listed
/// together with the per-peer reasons; boot then fails just as it would have failed verification.
pub(crate) async fn sync_public_material_from_peers<PubS, PrivS, G, R>(
    public_storage: &mut PubS,
    private_storage: &PrivS,
    key_entries: &HashMap<(RequestId, EpochId), KeyGenMetadata>,
    crs_entries: &HashMap<(RequestId, EpochId), CrsGenMetadata>,
    epoch_contexts: &BTreeMap<EpochId, ContextId>,
    ro_storage_getter: &G,
) -> anyhow::Result<PublicMaterialSyncReport>
where
    PubS: Storage + Send + Sync,
    PrivS: StorageReader + Sync,
    G: ReadOnlyS3StorageGetter<R>,
    R: StorageReader,
{
    let mut report = PublicMaterialSyncReport::default();
    let mut work: Vec<SyncWorkItem> = Vec::new();

    let latest_keys: HashMap<RequestId, (EpochId, &KeyGenMetadata)> = select_data_from_max_epoch(
        key_entries
            .iter()
            .map(|((id, epoch_id), metadata)| ((*id, *epoch_id), (*epoch_id, metadata))),
    );
    for (id, (epoch_id, metadata)) in latest_keys {
        let inner = match metadata {
            KeyGenMetadata::Current(inner) => inner,
            KeyGenMetadata::LegacyV0(_) => {
                tracing::info!(
                    "Keyset metadata for id={id} is legacy and has no digests; it cannot be \
                     synced from peers"
                );
                report.skipped_legacy.insert(id);
                continue;
            }
        };
        if let Err(e) = classify_current_public_material(&inner.key_digest_map) {
            // Verification runs right after the sync and produces the authoritative failure for
            // a malformed digest map; fetching against it would only muddy that report.
            tracing::warn!(
                "Keyset metadata for id={id} has an unexpected digest-map shape ({e:#}); \
                 leaving it to verification"
            );
            continue;
        }
        collect_out_of_sync_entries(
            public_storage,
            id,
            epoch_id,
            &inner.key_digest_map,
            &mut report,
            &mut work,
        )
        .await?;
    }

    let latest_crses: HashMap<RequestId, (EpochId, &CrsGenMetadata)> = select_data_from_max_epoch(
        crs_entries
            .iter()
            .map(|((id, epoch_id), metadata)| ((*id, *epoch_id), (*epoch_id, metadata))),
    );
    for (id, (epoch_id, metadata)) in latest_crses {
        let inner = match metadata {
            CrsGenMetadata::Current(inner) => inner,
            CrsGenMetadata::LegacyV0(_) => {
                tracing::info!(
                    "CRS metadata for id={id} is legacy and has no digest; it cannot be synced \
                     from peers"
                );
                report.skipped_legacy.insert(id);
                continue;
            }
        };
        let digest_map = BTreeMap::from([(PubDataType::CRS, inner.crs_digest.clone())]);
        collect_out_of_sync_entries(
            public_storage,
            id,
            epoch_id,
            &digest_map,
            &mut report,
            &mut work,
        )
        .await?;
    }

    // Fetch and persist. Failures are gathered rather than returned one at a time so the boot
    // log names everything that could not be repaired in one pass.
    let mut context_cache: HashMap<ContextId, crate::engine::context::ContextInfo> = HashMap::new();
    let mut failures: Vec<String> = Vec::new();
    for item in work {
        let SyncWorkItem {
            id,
            epoch_id,
            digests,
            reasons,
        } = item;
        let Some(context_id) = epoch_contexts.get(&epoch_id) else {
            failures.push(format!(
                "no context known for epoch {epoch_id} of id={id}; cannot resolve peers for {:?}",
                digests.keys().collect::<Vec<_>>()
            ));
            continue;
        };
        let context = match context_cache.entry(*context_id) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                match read_context_at_id(private_storage, context_id).await {
                    Ok(context) => entry.insert(context),
                    Err(e) => {
                        failures.push(format!(
                            "cannot read context {context_id} for epoch {epoch_id} of id={id}: {e:#}"
                        ));
                        continue;
                    }
                }
            }
        };

        let fetched = match fetch_verified_public_bytes_from_peers(
            &context.mpc_nodes,
            &id,
            &digests,
            ro_storage_getter,
        )
        .await
        {
            Ok(fetched) => fetched,
            Err(e) => {
                failures.push(format!("{e:#}"));
                continue;
            }
        };

        for (data_type, bytes) in fetched {
            // The fetcher returns exactly the requested entries, so a missing reason is a bug.
            let reason = reasons
                .get(&data_type)
                .expect("fetched an entry that was never requested");
            match reason {
                OutOfSync::Mismatch => {
                    tracing::warn!(
                        "Replacing public material {data_type} for id={id} with verified bytes \
                         from a peer"
                    );
                    // store_bytes never overwrites, so the corrupt entry is deleted first. The
                    // two steps are not atomic; a crash in between leaves the entry missing,
                    // which the missing-path of the next boot repairs.
                    public_storage
                        .delete_data(&id, &data_type.to_string())
                        .await?;
                    let outcome = public_storage
                        .store_bytes(&bytes, &id, &data_type.to_string())
                        .await?;
                    if outcome != StoreWriteOutcome::Created {
                        anyhow::bail!(
                            "public material {data_type} for id={id} still present after \
                             deletion; refusing to leave the mismatched bytes in place"
                        );
                    }
                    report.repaired.push((id, data_type));
                }
                OutOfSync::Missing => {
                    let outcome = public_storage
                        .store_bytes(&bytes, &id, &data_type.to_string())
                        .await?;
                    if outcome != StoreWriteOutcome::Created {
                        // Nothing else writes public storage this early in boot, so an entry
                        // appearing between the check and the store points at a work-list bug.
                        // Verification re-checks the entry right after, so only warn.
                        tracing::warn!(
                            "Public material {data_type} for id={id} appeared while syncing; \
                             kept the existing entry"
                        );
                    }
                    report.fetched.push((id, data_type));
                }
            }
        }
    }

    if !failures.is_empty() {
        anyhow::bail!(
            "public material could not be synced from peers: [{}]",
            failures.join("; ")
        );
    }
    Ok(report)
}

/// Check every entry of one ID's digest map against own public storage, recording consistent
/// entries in the report and queueing the rest as one work item.
async fn collect_out_of_sync_entries<PubS>(
    public_storage: &PubS,
    id: RequestId,
    epoch_id: EpochId,
    digest_map: &BTreeMap<PubDataType, Vec<u8>>,
    report: &mut PublicMaterialSyncReport,
    work: &mut Vec<SyncWorkItem>,
) -> anyhow::Result<()>
where
    PubS: Storage + Send + Sync,
{
    let mut digests = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    for (data_type, expected_digest) in digest_map {
        match out_of_sync(public_storage, &id, *data_type, expected_digest).await? {
            None => report.consistent += 1,
            Some(reason) => {
                digests.insert(*data_type, expected_digest.clone());
                reasons.insert(*data_type, reason);
            }
        }
    }
    if !digests.is_empty() {
        work.push(SyncWorkItem {
            id,
            epoch_id,
            digests,
            reasons,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::base::{DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY, KeyGenMetadataInner};
    use crate::engine::context::{ContextInfo, NodeInfo, SchemeDigests, SoftwareVersion};
    use crate::engine::material_integrity::ERR_SERVER_KEY_DIGEST_MISMATCH;
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::s3::{DummyReadOnlyS3Storage, DummyReadOnlyS3StorageGetter};
    use crate::vault::storage::store_context_at_id;
    use aes_prng::AesRng;
    use hashing::hash_element;
    use kms_grpc::ContextId;
    use rand::SeedableRng;
    use std::cell::RefCell;

    const PUBLIC_KEY_BYTES: &[u8] = b"public key bytes";
    const SERVER_KEY_BYTES: &[u8] = b"server key bytes";
    const CRS_BYTES: &[u8] = b"crs bytes";
    // The URL itself is never contacted: the dummy getter serves RamStorages. It only needs to
    // parse as an S3 URL.
    const NODE_URL: &str = "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/";

    fn digest_of(data_type: PubDataType, bytes: &[u8]) -> Vec<u8> {
        match data_type {
            PubDataType::CRS => hash_element(&DSEP_PUBDATA_CRS, bytes),
            _ => hash_element(&DSEP_PUBDATA_KEY, bytes),
        }
    }

    fn make_node(party_id: u32, url: &str) -> NodeInfo {
        NodeInfo {
            mpc_identity: format!("Node{party_id}"),
            party_id,
            external_url: "http://localhost:12345".to_string(),
            ca_cert: None,
            public_storage_url: url.to_string(),
            public_storage_prefix: None,
            extra_signer_addresses: vec![],
            scheme_digests: SchemeDigests::new(),
        }
    }

    fn getter_with(storages: Vec<RamStorage>) -> DummyReadOnlyS3StorageGetter {
        DummyReadOnlyS3StorageGetter {
            counter: RefCell::new(0),
            ram_storages: storages,
        }
    }

    async fn storage_with(id: &RequestId, entries: &[(PubDataType, &[u8])]) -> RamStorage {
        let mut storage = RamStorage::new();
        for (data_type, bytes) in entries {
            storage
                .store_bytes(bytes, id, &data_type.to_string())
                .await
                .unwrap();
        }
        storage
    }

    fn digests_for(entries: &[(PubDataType, &[u8])]) -> BTreeMap<PubDataType, Vec<u8>> {
        entries
            .iter()
            .map(|(data_type, bytes)| (*data_type, digest_of(*data_type, bytes)))
            .collect()
    }

    const KEYSET_ENTRIES: &[(PubDataType, &[u8])] = &[
        (PubDataType::PublicKey, PUBLIC_KEY_BYTES),
        (PubDataType::ServerKey, SERVER_KEY_BYTES),
    ];

    #[tokio::test]
    async fn fetcher_returns_bytes_from_first_working_peer() {
        let mut rng = AesRng::seed_from_u64(1);
        let id = RequestId::new_random(&mut rng);
        let nodes = vec![make_node(1, NODE_URL), make_node(2, NODE_URL)];
        let getter = getter_with(vec![storage_with(&id, KEYSET_ENTRIES).await]);

        let fetched = fetch_verified_public_bytes_from_peers::<_, DummyReadOnlyS3Storage>(
            &nodes,
            &id,
            &digests_for(KEYSET_ENTRIES),
            &getter,
        )
        .await
        .unwrap();

        assert_eq!(fetched[&PubDataType::PublicKey], PUBLIC_KEY_BYTES);
        assert_eq!(fetched[&PubDataType::ServerKey], SERVER_KEY_BYTES);
        // The first working peer satisfies everything, so only one storage is built.
        assert_eq!(*getter.counter.borrow(), 1);
    }

    #[tokio::test]
    async fn fetcher_falls_back_when_first_peer_has_nothing() {
        let mut rng = AesRng::seed_from_u64(2);
        let id = RequestId::new_random(&mut rng);
        let nodes = vec![make_node(1, NODE_URL), make_node(2, NODE_URL)];
        // The dummy getter serves storages in call order: the first attempted peer gets the
        // empty one, whichever node the shuffle puts first.
        let getter = getter_with(vec![
            RamStorage::new(),
            storage_with(&id, KEYSET_ENTRIES).await,
        ]);

        fetch_verified_public_bytes_from_peers::<_, DummyReadOnlyS3Storage>(
            &nodes,
            &id,
            &digests_for(KEYSET_ENTRIES),
            &getter,
        )
        .await
        .unwrap();

        assert_eq!(*getter.counter.borrow(), 2);
    }

    #[tokio::test]
    async fn fetcher_errors_cleanly_on_empty_peer_list() {
        // Regression: the pre-generalization fetchers indexed errors[0] and panicked here.
        let mut rng = AesRng::seed_from_u64(3);
        let id = RequestId::new_random(&mut rng);
        let getter = getter_with(vec![]);

        let err = fetch_verified_public_bytes_from_peers::<_, DummyReadOnlyS3Storage>(
            &[],
            &id,
            &digests_for(KEYSET_ENTRIES),
            &getter,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains(ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn fetcher_skips_peer_with_empty_url() {
        // Regression: the pre-generalization fetchers aborted the whole loop on the first
        // malformed URL. The default context records empty URLs for every peer.
        let mut rng = AesRng::seed_from_u64(4);
        let id = RequestId::new_random(&mut rng);
        let nodes = vec![make_node(1, ""), make_node(2, NODE_URL)];
        let getter = getter_with(vec![storage_with(&id, KEYSET_ENTRIES).await]);

        fetch_verified_public_bytes_from_peers::<_, DummyReadOnlyS3Storage>(
            &nodes,
            &id,
            &digests_for(KEYSET_ENTRIES),
            &getter,
        )
        .await
        .unwrap();

        // The empty-URL node never reaches the getter.
        assert_eq!(*getter.counter.borrow(), 1);
    }

    #[tokio::test]
    async fn fetcher_rejects_peers_whose_bytes_mismatch() {
        let mut rng = AesRng::seed_from_u64(5);
        let id = RequestId::new_random(&mut rng);
        let nodes = vec![make_node(1, NODE_URL)];
        let getter = getter_with(vec![storage_with(&id, KEYSET_ENTRIES).await]);

        let wrong_digests: BTreeMap<PubDataType, Vec<u8>> = BTreeMap::from([
            (PubDataType::ServerKey, vec![0, 1, 2, 3]),
            (PubDataType::PublicKey, vec![4, 5, 6, 7]),
        ]);
        let err = fetch_verified_public_bytes_from_peers::<_, DummyReadOnlyS3Storage>(
            &nodes,
            &id,
            &wrong_digests,
            &getter,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains(ERR_SERVER_KEY_DIGEST_MISMATCH),
            "unexpected error: {err}"
        );
    }

    /// Everything a sync test needs: one keyset and one CRS under one epoch/context, a private
    /// storage holding the context (one peer whose storage the dummy getter serves), and the
    /// metadata maps as boot would pass them.
    struct SyncFixture {
        public_storage: RamStorage,
        private_storage: RamStorage,
        key_entries: HashMap<(RequestId, EpochId), KeyGenMetadata>,
        crs_entries: HashMap<(RequestId, EpochId), CrsGenMetadata>,
        epoch_contexts: BTreeMap<EpochId, ContextId>,
        peer_storage: RamStorage,
        key_id: RequestId,
        crs_id: RequestId,
    }

    async fn sync_fixture(seed: u64) -> SyncFixture {
        let mut rng = AesRng::seed_from_u64(seed);
        let key_id = RequestId::new_random(&mut rng);
        let crs_id = RequestId::new_random(&mut rng);
        let epoch_id = EpochId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);

        let key_metadata = KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id: RequestId::new_random(&mut rng),
            key_digest_map: digests_for(KEYSET_ENTRIES),
            extra_data: None,
            eip712_domain: None,
            external_signature: vec![],
            signatures: vec![],
        });
        let crs_metadata = CrsGenMetadata::Current(crate::engine::base::CrsGenMetadataInner {
            crs_id,
            crs_digest: digest_of(PubDataType::CRS, CRS_BYTES),
            max_num_bits: 2048,
            extra_data: None,
            eip712_domain: None,
            external_signature: vec![],
            signatures: vec![],
        });

        let mut private_storage = RamStorage::new();
        let context = ContextInfo {
            mpc_nodes: vec![make_node(1, NODE_URL)],
            context_id,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
            pcr_values: vec![],
        };
        store_context_at_id(&mut private_storage, &context_id, &context)
            .await
            .unwrap();

        let mut peer_storage = storage_with(&key_id, KEYSET_ENTRIES).await;
        peer_storage
            .store_bytes(CRS_BYTES, &crs_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        SyncFixture {
            public_storage: RamStorage::new(),
            private_storage,
            key_entries: HashMap::from([((key_id, epoch_id), key_metadata)]),
            crs_entries: HashMap::from([((crs_id, epoch_id), crs_metadata)]),
            epoch_contexts: BTreeMap::from([(epoch_id, context_id)]),
            peer_storage,
            key_id,
            crs_id,
        }
    }

    #[tokio::test]
    async fn sync_fetches_and_stores_missing_material() {
        let mut fixture = sync_fixture(10).await;
        // One fetch per out-of-sync ID: the keyset and the CRS.
        let getter = getter_with(vec![
            fixture.peer_storage.clone(),
            fixture.peer_storage.clone(),
        ]);

        let report = sync_public_material_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &mut fixture.public_storage,
            &fixture.private_storage,
            &fixture.key_entries,
            &fixture.crs_entries,
            &fixture.epoch_contexts,
            &getter,
        )
        .await
        .unwrap();

        assert_eq!(report.fetched.len(), 3);
        assert!(report.repaired.is_empty());
        assert_eq!(report.consistent, 0);
        for (data_type, bytes) in KEYSET_ENTRIES {
            let stored = fixture
                .public_storage
                .load_bytes(&fixture.key_id, &data_type.to_string())
                .await
                .unwrap();
            assert_eq!(&stored, bytes);
        }
        let stored_crs = fixture
            .public_storage
            .load_bytes(&fixture.crs_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();
        assert_eq!(stored_crs, CRS_BYTES);
    }

    #[tokio::test]
    async fn sync_makes_no_peer_calls_when_storage_is_consistent() {
        let mut fixture = sync_fixture(11).await;
        // Own public storage already holds everything the metadata describes.
        fixture.public_storage = fixture.peer_storage.clone();
        let getter = getter_with(vec![]);

        let report = sync_public_material_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &mut fixture.public_storage,
            &fixture.private_storage,
            &fixture.key_entries,
            &fixture.crs_entries,
            &fixture.epoch_contexts,
            &getter,
        )
        .await
        .unwrap();

        assert_eq!(
            report,
            PublicMaterialSyncReport {
                consistent: 3,
                ..Default::default()
            }
        );
        assert_eq!(*getter.counter.borrow(), 0);
    }

    #[tokio::test]
    async fn sync_replaces_mismatched_material() {
        let mut fixture = sync_fixture(12).await;
        // Start consistent, then corrupt the stored server key.
        fixture.public_storage = fixture.peer_storage.clone();
        fixture
            .public_storage
            .delete_data(&fixture.key_id, &PubDataType::ServerKey.to_string())
            .await
            .unwrap();
        fixture
            .public_storage
            .store_bytes(
                b"truncated server key",
                &fixture.key_id,
                &PubDataType::ServerKey.to_string(),
            )
            .await
            .unwrap();
        let getter = getter_with(vec![fixture.peer_storage.clone()]);

        let report = sync_public_material_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &mut fixture.public_storage,
            &fixture.private_storage,
            &fixture.key_entries,
            &fixture.crs_entries,
            &fixture.epoch_contexts,
            &getter,
        )
        .await
        .unwrap();

        assert_eq!(
            report.repaired,
            vec![(fixture.key_id, PubDataType::ServerKey)]
        );
        assert!(report.fetched.is_empty());
        assert_eq!(report.consistent, 2);
        let stored = fixture
            .public_storage
            .load_bytes(&fixture.key_id, &PubDataType::ServerKey.to_string())
            .await
            .unwrap();
        assert_eq!(stored, SERVER_KEY_BYTES);
    }

    #[tokio::test]
    async fn sync_skips_legacy_metadata() {
        let mut fixture = sync_fixture(13).await;
        // Replace the key metadata with a legacy entry: no digest, nothing to sync, and the
        // missing public objects are left for verification's presence check.
        let (key, _) = fixture
            .key_entries
            .drain()
            .next()
            .expect("fixture has one key entry");
        fixture
            .key_entries
            .insert(key, KeyGenMetadata::LegacyV0(HashMap::new()));
        // The CRS is still current and missing, so one fetch happens.
        let getter = getter_with(vec![fixture.peer_storage.clone()]);

        let report = sync_public_material_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &mut fixture.public_storage,
            &fixture.private_storage,
            &fixture.key_entries,
            &fixture.crs_entries,
            &fixture.epoch_contexts,
            &getter,
        )
        .await
        .unwrap();

        assert!(report.skipped_legacy.contains(&fixture.key_id));
        assert_eq!(report.fetched, vec![(fixture.crs_id, PubDataType::CRS)]);
        assert!(
            !fixture
                .public_storage
                .data_exists(&fixture.key_id, &PubDataType::PublicKey.to_string())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn sync_fails_when_epoch_has_no_context() {
        let mut fixture = sync_fixture(14).await;
        fixture.epoch_contexts.clear();
        let getter = getter_with(vec![]);

        let err = sync_public_material_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &mut fixture.public_storage,
            &fixture.private_storage,
            &fixture.key_entries,
            &fixture.crs_entries,
            &fixture.epoch_contexts,
            &getter,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("no context known for epoch"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn sync_fails_when_no_peer_can_supply_the_material() {
        let mut fixture = sync_fixture(15).await;
        // The single peer's storage is empty, so nothing can be validated and fetched.
        let getter = getter_with(vec![RamStorage::new(), RamStorage::new()]);

        let err = sync_public_material_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &mut fixture.public_storage,
            &fixture.private_storage,
            &fixture.key_entries,
            &fixture.crs_entries,
            &fixture.epoch_contexts,
            &getter,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains(ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn sync_fetches_missing_compressed_keyset() {
        let mut rng = AesRng::seed_from_u64(16);
        let key_id = RequestId::new_random(&mut rng);
        let epoch_id = EpochId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let entries: &[(PubDataType, &[u8])] = &[
            (PubDataType::PublicKey, PUBLIC_KEY_BYTES),
            (PubDataType::CompressedXofKeySet, b"compressed keyset bytes"),
        ];

        let key_metadata = KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id: RequestId::new_random(&mut rng),
            key_digest_map: digests_for(entries),
            extra_data: None,
            eip712_domain: None,
            external_signature: vec![],
            signatures: vec![],
        });
        let mut private_storage = RamStorage::new();
        let context = ContextInfo {
            mpc_nodes: vec![make_node(1, NODE_URL)],
            context_id,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
            pcr_values: vec![],
        };
        store_context_at_id(&mut private_storage, &context_id, &context)
            .await
            .unwrap();
        let getter = getter_with(vec![storage_with(&key_id, entries).await]);

        let mut public_storage = RamStorage::new();
        let report = sync_public_material_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &mut public_storage,
            &private_storage,
            &HashMap::from([((key_id, epoch_id), key_metadata)]),
            &HashMap::new(),
            &BTreeMap::from([(epoch_id, context_id)]),
            &getter,
        )
        .await
        .unwrap();

        assert_eq!(report.fetched.len(), 2);
        let stored = public_storage
            .load_bytes(&key_id, &PubDataType::CompressedXofKeySet.to_string())
            .await
            .unwrap();
        assert_eq!(stored, b"compressed keyset bytes");
    }
}
