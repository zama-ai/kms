//! Background checks of the dependencies of a KMS server.
//!
//! The checks record their results in the [`HealthState`] of the server, which reports them on
//! `/healthz` and in the `kms_health_dependency_up` metric. They change neither liveness nor
//! readiness. Each check only reads: a storage check sends one existence request, and a peer check
//! sends the health message of the core-to-core protocol.

use crate::consts::SIGNING_KEY_ID;
use crate::engine::threshold::service::session::ImmutableSessionMaker;
use crate::vault::storage::{
    Storage, StorageExt, StorageReader, crypto_material::CryptoMaterialStorage,
};
use kms_grpc::kms::v1::HealthStatus;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use observability::health::HealthState;
use std::collections::HashMap;
use std::time::Duration;
use threshold_networking::health_check::HealthCheckStatus;
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;

/// Dependency name of the public storage.
pub(crate) const PUBLIC_STORAGE: &str = "public_storage";
/// Dependency name of the private storage.
pub(crate) const PRIVATE_STORAGE: &str = "private_storage";
/// Dependency name of the backup storage. It is checked only when a backup vault is configured.
pub(crate) const BACKUP_STORAGE: &str = "backup_storage";
/// Dependency name of the MPC state. It passes when the server has an MPC context and an epoch.
pub(crate) const MPC_CONTEXT: &str = "mpc_context";
/// Dependency name of the peers. It fails when the newest MPC context of this party has too few
/// reachable parties.
pub(crate) const PEERS: &str = "peers";

/// Time between the end of one round of a check and the start of its next round.
const CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum time that a storage check waits for the storage lock, and then for the storage.
const STORAGE_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// Number of rounds in a row in which a storage check can skip a storage whose lock another task
/// holds. After that, the storage fails, because a request that hangs also keeps the lock.
const MAX_SKIPPED_ROUNDS: u32 = 3;

/// Consecutive skipped rounds of each storage check, by dependency name.
type SkippedRounds = HashMap<&'static str, u32>;

/// Starts the checks of the storages in `storage`, and of the MPC state in `session_maker` for a
/// threshold server. The task stops after the server starts its shutdown.
pub(crate) fn spawn_dependency_checks<PubS, PrivS>(
    health: HealthState,
    storage: CryptoMaterialStorage<PubS, PrivS>,
    session_maker: Option<ImmutableSessionMaker>,
) -> JoinHandle<()>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
{
    // Register the dependencies before the first round, so that the server is not healthy while
    // the first checks run.
    health.expect_dependency(PUBLIC_STORAGE);
    health.expect_dependency(PRIVATE_STORAGE);
    if storage.backup_vault.is_some() {
        health.expect_dependency(BACKUP_STORAGE);
    }
    if session_maker.is_some() {
        health.expect_dependency(MPC_CONTEXT);
        health.expect_dependency(PEERS);
    }
    tokio::spawn(async move {
        // Separate loops, so that a slow peer check does not delay the storage checks.
        let storage_checks = async {
            let mut skipped_rounds = SkippedRounds::new();
            while !health.is_shutting_down() {
                check_storages(
                    &health,
                    &storage,
                    &mut skipped_rounds,
                    STORAGE_CHECK_TIMEOUT,
                )
                .await;
                tokio::time::sleep(CHECK_INTERVAL).await;
            }
        };
        let mpc_checks = async {
            let Some(session_maker) = &session_maker else {
                return;
            };
            while !health.is_shutting_down() {
                check_mpc(&health, session_maker).await;
                tokio::time::sleep(CHECK_INTERVAL).await;
            }
        };
        tokio::join!(storage_checks, mpc_checks);
    })
}

/// Checks that the public, private and backup storages answer a read request within `timeout`.
///
/// A storage passes when the request succeeds, whether or not the object exists. When another task
/// holds the storage lock for longer than `timeout`, the check skips that storage and keeps its
/// last result, because a long write, such as the upload of a key, holds the lock. After
/// [`MAX_SKIPPED_ROUNDS`] skipped rounds in a row, the storage fails.
async fn check_storages<PubS, PrivS>(
    health: &HealthState,
    storage: &CryptoMaterialStorage<PubS, PrivS>,
    skipped_rounds: &mut SkippedRounds,
    timeout: Duration,
) where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
{
    if let Some(public_storage) = lock_for_check(
        health,
        PUBLIC_STORAGE,
        &storage.public_storage,
        skipped_rounds,
        timeout,
    )
    .await
    {
        let data_type = PubDataType::VerfKey.to_string();
        check_storage(
            health,
            PUBLIC_STORAGE,
            &*public_storage,
            &data_type,
            timeout,
        )
        .await;
    }
    if let Some(private_storage) = lock_for_check(
        health,
        PRIVATE_STORAGE,
        &storage.private_storage,
        skipped_rounds,
        timeout,
    )
    .await
    {
        let data_type = PrivDataType::SigningKey.to_string();
        check_storage(
            health,
            PRIVATE_STORAGE,
            &*private_storage,
            &data_type,
            timeout,
        )
        .await;
    }
    if let Some(backup_vault) = &storage.backup_vault
        && let Some(backup_vault) = lock_for_check(
            health,
            BACKUP_STORAGE,
            backup_vault,
            skipped_rounds,
            timeout,
        )
        .await
    {
        // The request goes to the storage under the vault, because the vault maps the data type
        // through its keychain, and a custodian keychain has no mapping before its first backup.
        let data_type = PrivDataType::SigningKey.to_string();
        check_storage(
            health,
            BACKUP_STORAGE,
            &backup_vault.storage,
            &data_type,
            timeout,
        )
        .await;
    }
}

/// Locks `storage` for a check, or returns `None` and counts a skipped round when another task
/// holds the lock for longer than `timeout`.
async fn lock_for_check<'a, T>(
    health: &HealthState,
    name: &'static str,
    storage: &'a Mutex<T>,
    skipped_rounds: &mut SkippedRounds,
    timeout: Duration,
) -> Option<MutexGuard<'a, T>> {
    if let Ok(guard) = tokio::time::timeout(timeout, storage.lock()).await {
        skipped_rounds.remove(name);
        return Some(guard);
    }
    let skipped = skipped_rounds.entry(name).or_insert(0);
    *skipped += 1;
    if *skipped >= MAX_SKIPPED_ROUNDS {
        tracing::warn!(
            dependency = name,
            skipped_rounds = *skipped,
            "Health check of a storage fails: another task holds the storage lock for too many rounds in a row"
        );
        health.set_dependency(name, false);
    } else {
        tracing::debug!(
            dependency = name,
            skipped_rounds = *skipped,
            "Health check of a storage skipped: another task holds the storage lock"
        );
    }
    None
}

async fn check_storage<S: StorageReader + Sync>(
    health: &HealthState,
    name: &'static str,
    storage: &S,
    data_type: &str,
    timeout: Duration,
) {
    let result =
        tokio::time::timeout(timeout, storage.data_exists(&SIGNING_KEY_ID, data_type)).await;
    let healthy = match result {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::warn!(
                dependency = name,
                storage = storage.info(),
                error = %format!("{e:#}"),
                "Health check of a storage fails: the read request returns an error"
            );
            false
        }
        Err(_) => {
            tracing::warn!(
                dependency = name,
                storage = storage.info(),
                timeout_ms = timeout.as_millis(),
                "Health check of a storage fails: the storage does not answer within the timeout"
            );
            false
        }
    };
    health.set_dependency(name, healthy);
}

/// Checks that the server has an MPC context and an epoch, and that the newest MPC context of this
/// party has enough reachable parties.
async fn check_mpc(health: &HealthState, session_maker: &ImmutableSessionMaker) {
    let context_count = session_maker.context_count().await;
    let epoch_count = session_maker.epoch_count().await;
    let has_context = context_count > 0 && epoch_count > 0;
    if !has_context {
        tracing::warn!(
            context_count,
            epoch_count,
            "Health check of the MPC state fails: the server has no MPC context or no epoch"
        );
    }
    health.set_dependency(MPC_CONTEXT, has_context);
    health.set_dependency(PEERS, check_peers(session_maker).await);
}

async fn check_peers(session_maker: &ImmutableSessionMaker) -> bool {
    // Older contexts can keep retired parties until someone destroys them, so only the newest
    // context counts.
    let (context_id, session) = match session_maker.get_healthcheck_session_newest_context().await {
        Ok(Some(newest)) => newest,
        Ok(None) => return true,
        Err(e) => {
            tracing::warn!(
                error = %format!("{e:#}"),
                "Health check of the peers fails: the health check session of the newest MPC context cannot be created"
            );
            return false;
        }
    };

    let results = match session.run_healthcheck().await {
        Ok(results) => results,
        Err(e) => {
            tracing::warn!(
                %context_id,
                error = %format!("{e:#}"),
                "Health check of the peers fails: the health check of the newest MPC context returns an error"
            );
            return false;
        }
    };
    let total_nodes = session.get_num_parties() as u32;
    // This party is reachable.
    let mut nodes_reachable = 1;
    let mut unreachable_parties = Vec::new();
    for ((role, _identity), result) in results {
        if let HealthCheckStatus::Ok(_) = result {
            nodes_reachable += 1;
        } else {
            unreachable_parties.push(role.one_based());
        }
    }
    if peer_quorum_status(nodes_reachable, total_nodes) == HealthStatus::Unhealthy {
        unreachable_parties.sort_unstable();
        tracing::warn!(
            %context_id,
            nodes_reachable,
            total_nodes,
            ?unreachable_parties,
            "Health check of the peers fails: too few parties of the newest MPC context are reachable"
        );
        return false;
    }
    true
}

/// Returns the minimum threshold of reachable parties to be able to reconstruct anything in an MPC
/// context of `total_nodes` parties.
pub(crate) fn min_threshold(total_nodes: u32) -> u32 {
    (total_nodes / 3) + 1
}

/// Classifies an MPC context of `total_nodes` parties, of which `nodes_reachable` are reachable.
/// The count of reachable parties includes this party.
pub(crate) fn peer_quorum_status(nodes_reachable: u32, total_nodes: u32) -> HealthStatus {
    let min_nodes_for_healthy = (2 * total_nodes) / 3 + 1; // 2/3 majority + 1
    let min_threshold = min_threshold(total_nodes);
    if nodes_reachable >= total_nodes {
        HealthStatus::Optimal // all nodes online and reachable
    } else if nodes_reachable >= min_nodes_for_healthy {
        HealthStatus::Healthy // sufficient 2/3 majority but not all nodes
    } else if nodes_reachable > min_threshold {
        HealthStatus::Degraded // above minimum threshold but below 2/3
    } else {
        HealthStatus::Unhealthy // insufficient nodes for operations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::rng_source::TaskRngs;
    use crate::engine::threshold::service::session::SessionMaker;
    use crate::vault::storage::RootEntries;
    use crate::vault::storage::ram::RamStorage;
    use kms_grpc::RequestId;
    use kms_grpc::identifiers::ContextId;
    use observability::health::DependencyStatus;
    use serde::de::DeserializeOwned;
    use std::collections::HashMap;
    use std::collections::{BTreeMap, HashSet};
    use tfhe::{Unversionize, named::Named};
    use threshold_types::party::{Identity, RoleAssignment};
    use threshold_types::role::Role;

    /// Storage whose existence request fails, or never answers.
    struct UnreachableStorage {
        hangs: bool,
    }

    impl StorageReader for UnreachableStorage {
        async fn data_exists(
            &self,
            _data_id: &RequestId,
            _data_type: &str,
        ) -> anyhow::Result<bool> {
            if self.hangs {
                std::future::pending::<()>().await;
            }
            Err(anyhow::anyhow!("connection refused"))
        }

        async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
            &self,
            _data_id: &RequestId,
            _data_type: &str,
        ) -> anyhow::Result<T> {
            unimplemented!("the health check only sends existence requests")
        }

        async fn load_bytes(
            &self,
            _data_id: &RequestId,
            _data_type: &str,
        ) -> anyhow::Result<Vec<u8>> {
            unimplemented!("the health check only sends existence requests")
        }

        async fn all_data_ids(&self, _data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
            unimplemented!("the health check only sends existence requests")
        }

        async fn all_data_types(&self) -> anyhow::Result<RootEntries> {
            unimplemented!("the health check only sends existence requests")
        }

        fn info(&self) -> String {
            "unreachable test storage".to_string()
        }
    }

    const TEST_TIMEOUT: Duration = Duration::from_millis(100);

    #[tokio::test]
    async fn reachable_storages_pass() {
        let (health, _service) = HealthState::new().await;
        let storage = CryptoMaterialStorage::from(RamStorage::new(), RamStorage::new(), None);
        check_storages(&health, &storage, &mut SkippedRounds::new(), TEST_TIMEOUT).await;
        assert_eq!(
            health.dependencies(),
            BTreeMap::from([
                (PRIVATE_STORAGE, DependencyStatus::Ok),
                (PUBLIC_STORAGE, DependencyStatus::Ok)
            ])
        );
    }

    #[tokio::test]
    async fn storage_with_read_error_fails() {
        let (health, _service) = HealthState::new().await;
        let storage = UnreachableStorage { hangs: false };
        check_storage(&health, PUBLIC_STORAGE, &storage, "VerfKey", TEST_TIMEOUT).await;
        assert_eq!(
            health.dependencies(),
            BTreeMap::from([(PUBLIC_STORAGE, DependencyStatus::Failed)])
        );
    }

    #[tokio::test]
    async fn storage_without_answer_fails() {
        let (health, _service) = HealthState::new().await;
        let storage = UnreachableStorage { hangs: true };
        check_storage(&health, PUBLIC_STORAGE, &storage, "VerfKey", TEST_TIMEOUT).await;
        assert_eq!(
            health.dependencies(),
            BTreeMap::from([(PUBLIC_STORAGE, DependencyStatus::Failed)])
        );
    }

    #[tokio::test]
    async fn locked_storage_keeps_last_result() {
        let (health, _service) = HealthState::new().await;
        let storage = CryptoMaterialStorage::from(RamStorage::new(), RamStorage::new(), None);
        health.set_dependency(PUBLIC_STORAGE, false);

        let _write_in_progress = storage.public_storage.lock().await;
        check_storages(&health, &storage, &mut SkippedRounds::new(), TEST_TIMEOUT).await;
        assert_eq!(
            health.dependencies(),
            BTreeMap::from([
                (PRIVATE_STORAGE, DependencyStatus::Ok),
                (PUBLIC_STORAGE, DependencyStatus::Failed)
            ])
        );
    }

    #[tokio::test]
    async fn storage_locked_for_too_many_rounds_fails() {
        let (health, _service) = HealthState::new().await;
        let storage = CryptoMaterialStorage::from(RamStorage::new(), RamStorage::new(), None);
        let mut skipped_rounds = SkippedRounds::new();
        check_storages(&health, &storage, &mut skipped_rounds, TEST_TIMEOUT).await;
        assert_eq!(
            health.dependencies().get(PUBLIC_STORAGE),
            Some(&DependencyStatus::Ok)
        );

        let write_in_progress = storage.public_storage.lock().await;
        for _ in 1..MAX_SKIPPED_ROUNDS {
            check_storages(&health, &storage, &mut skipped_rounds, TEST_TIMEOUT).await;
            assert_eq!(
                health.dependencies().get(PUBLIC_STORAGE),
                Some(&DependencyStatus::Ok)
            );
        }
        check_storages(&health, &storage, &mut skipped_rounds, TEST_TIMEOUT).await;
        assert_eq!(
            health.dependencies().get(PUBLIC_STORAGE),
            Some(&DependencyStatus::Failed)
        );

        // Once the lock is free again, the next round checks the storage and resets the count.
        drop(write_in_progress);
        check_storages(&health, &storage, &mut skipped_rounds, TEST_TIMEOUT).await;
        assert_eq!(
            health.dependencies().get(PUBLIC_STORAGE),
            Some(&DependencyStatus::Ok)
        );
        assert!(skipped_rounds.is_empty());
    }

    #[tokio::test]
    async fn server_without_context_fails_mpc_check() {
        let (health, _service) = HealthState::new().await;
        let session_maker =
            SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(0)).make_immutable();
        check_mpc(&health, &session_maker).await;
        // Without a context there is no peer to reach, so only the MPC state check fails.
        assert_eq!(
            health.dependencies(),
            BTreeMap::from([
                (MPC_CONTEXT, DependencyStatus::Failed),
                (PEERS, DependencyStatus::Ok)
            ])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dependency_checks_run_until_shutdown() {
        let (health, _service) = HealthState::new().await;
        let storage = CryptoMaterialStorage::from(RamStorage::new(), RamStorage::new(), None);
        let checks = spawn_dependency_checks(health.clone(), storage, None);
        // The paused clock keeps the first round from running before this check.
        assert_eq!(
            health.dependencies(),
            BTreeMap::from([
                (PRIVATE_STORAGE, DependencyStatus::Pending),
                (PUBLIC_STORAGE, DependencyStatus::Pending)
            ])
        );

        tokio::time::sleep(3 * CHECK_INTERVAL).await;
        assert!(!checks.is_finished());
        assert_eq!(
            health.dependencies(),
            BTreeMap::from([
                (PRIVATE_STORAGE, DependencyStatus::Ok),
                (PUBLIC_STORAGE, DependencyStatus::Ok)
            ])
        );

        health.mark_shutting_down().await;
        tokio::time::timeout(2 * CHECK_INTERVAL, checks)
            .await
            .expect("the checks must stop after the shutdown starts")
            .unwrap();
    }

    /// Returns a context ID in the format of the protocol config contract: type byte 7, then
    /// the counter.
    fn counter_context_id(counter: u8) -> ContextId {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        bytes[31] = counter;
        ContextId::from_bytes(bytes)
    }

    /// Returns `num_parties` parties on local ports that no server listens on, so that every
    /// connection is refused at once. This party has role 1.
    fn unreachable_parties(num_parties: usize) -> RoleAssignment<Role> {
        let mut inner = HashMap::new();
        for index in 1..=num_parties {
            // The listener closes at the end of the iteration, so the port stays free.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            inner.insert(
                Role::indexed_from_one(index),
                Identity::new("127.0.0.1".to_string(), port, None),
            );
        }
        RoleAssignment { inner }
    }

    #[tokio::test]
    async fn unreachable_peers_of_newest_context_fail() {
        let session_maker = SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(1));
        session_maker
            .add_test_context(counter_context_id(1), unreachable_parties(1))
            .await;
        session_maker
            .add_test_context(counter_context_id(2), unreachable_parties(4))
            .await;
        assert!(!check_peers(&session_maker.make_immutable()).await);
    }

    #[tokio::test]
    async fn only_newest_context_is_checked() {
        let session_maker = SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(2));
        // The old context has 4 unreachable parties. The newest context has only this party,
        // so all its parties are reachable.
        session_maker
            .add_test_context(counter_context_id(1), unreachable_parties(4))
            .await;
        session_maker
            .add_test_context(counter_context_id(2), unreachable_parties(1))
            .await;
        assert!(check_peers(&session_maker.make_immutable()).await);
    }

    #[test]
    fn peer_quorum_status_of_13_parties() {
        assert_eq!(peer_quorum_status(13, 13), HealthStatus::Optimal);
        assert_eq!(peer_quorum_status(12, 13), HealthStatus::Healthy);
        assert_eq!(peer_quorum_status(9, 13), HealthStatus::Healthy);
        assert_eq!(peer_quorum_status(8, 13), HealthStatus::Degraded);
        assert_eq!(peer_quorum_status(6, 13), HealthStatus::Degraded);
        assert_eq!(peer_quorum_status(5, 13), HealthStatus::Unhealthy);
        assert_eq!(peer_quorum_status(1, 13), HealthStatus::Unhealthy);
    }

    #[test]
    fn peer_quorum_status_of_4_parties() {
        assert_eq!(peer_quorum_status(4, 4), HealthStatus::Optimal);
        assert_eq!(peer_quorum_status(3, 4), HealthStatus::Healthy);
        assert_eq!(peer_quorum_status(2, 4), HealthStatus::Unhealthy);
    }
}
