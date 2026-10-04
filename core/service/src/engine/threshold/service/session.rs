// === Standard Library ===
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Weak},
};

use crate::engine::{
    context::{ContextInfo, SignerAddress},
    rng_source::{RngSource, RngSourceError},
    threshold::service::epoch_manager::EpochData,
    utils::MetricedError,
};

// === External Crates ===
#[cfg(test)]
use aes_prng::AesRng;
use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};
use kms_grpc::{EpochId, RequestId, identifiers::ContextId};
use threshold_execution::{
    runtime::sessions::{
        base_session::{BaseSession, TwoSetsBaseSession},
        session_parameters::{
            GenericParameterHandles, SessionParameters, TwoSetsSessionParameters,
        },
        small_session::SmallSession,
    },
    small_execution::prss::{DerivePRSSState, PRSSSetup},
};
use threshold_networking::{
    grpc::GrpcNetworkingManager, health_check::HealthCheckSession, tls::AttestedVerifier,
};
// Only used by the `#[cfg(test)]` dummy-session constructors below.
#[cfg(test)]
use threshold_networking::grpc::CoreToCoreNetworkConfig;
use threshold_types::role::{DualRole, Role, TwoSetsRole, TwoSetsThreshold};

#[cfg(test)]
use crate::engine::rng_source::TaskRngs;
#[cfg(test)]
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use thiserror::Error;
use threshold_types::session_id::SessionId;
use threshold_types::{
    network::NetworkMode,
    party::{Identity, MpcIdentity, RoleAssignment},
};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
use tonic::Code;

struct Context {
    // The ID under which the session maker stores this context.
    context_id: ContextId,
    // I may not belong to all the contexts I am aware of
    // especially in the case of resharing where I only belong
    // in one of the two contexts at play.
    my_role: Option<Role>,
    // A Context always hold only a RoleAssignment on Role
    // to build a RoleAssignment on a TwoSetRole,
    // we need 2 contexts
    role_assignment: RoleAssignment<Role>,
    // Signer address of each party whose node lists one in the context. A party without a
    // listed signer address has no entry.
    signers: HashMap<Role, SignerAddress>,
    threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PRSSSetupCombinedVersions {
    V0(PRSSSetupCombined),
}

/// Public because it's used by storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(PRSSSetupCombinedVersions)]
pub struct PRSSSetupCombined {
    pub prss_setup_z64: PRSSSetup<ResiduePolyF4Z64>,
    pub prss_setup_z128: PRSSSetup<ResiduePolyF4Z128>,
    pub num_parties: u8,
    pub threshold: u8,
}

impl tfhe::named::Named for PRSSSetupCombined {
    const NAME: &'static str = "kms::PRSSSetupCombined";
}

type ContextMap = HashMap<ContextId, Context>;

/// Hands out one lock per ID, keyed by the identifier type of the guarded resource.
///
/// Weak entries ensure rejected requests for random IDs do not grow the registry forever.
/// The owned lock guards taken by the callers keep their lock alive for exactly the lifecycle
/// operation.
#[derive(Clone)]
struct LockRegistry<Id> {
    locks: Arc<Mutex<HashMap<Id, Weak<RwLock<()>>>>>,
}

// Hand-written because `#[derive(Default)]` would add a spurious `Id: Default` bound.
impl<Id> Default for LockRegistry<Id> {
    fn default() -> Self {
        Self {
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<Id: Copy + Eq + Hash> LockRegistry<Id> {
    async fn lock(&self, id: &Id) -> Arc<RwLock<()>> {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(id).and_then(Weak::upgrade) {
            return lock;
        }

        let lock = Arc::new(RwLock::new(()));
        locks.insert(*id, Arc::downgrade(&lock));
        lock
    }
}

#[derive(Clone, Default)]
struct LifecycleCoordinator {
    context_locks: LockRegistry<ContextId>,
    epoch_locks: LockRegistry<EpochId>,
}

/// Identifies the lifecycle resource that is already held by a conflicting operation.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum LifecycleConflict {
    /// A context is in use while destruction starts, or destruction already holds it.
    #[error("MPC context {0} has a conflicting lifecycle operation in progress")]
    Context(ContextId),
    /// An epoch is in use while destruction starts, or destruction already holds it.
    #[error("epoch {0} has a conflicting lifecycle operation in progress")]
    Epoch(EpochId),
}

/// Keeps an epoch creation and its resharing source mutually exclusive with destruction.
#[derive(Debug)]
pub(crate) struct EpochCreationLease {
    _target_context: OwnedRwLockReadGuard<()>,
    _target_epoch: OwnedRwLockReadGuard<()>,
    _resharing_source: Option<(OwnedRwLockReadGuard<()>, OwnedRwLockReadGuard<()>)>,
}

/// Prevents epoch creation for a context while that context and its epochs are destroyed.
#[derive(Debug)]
pub(crate) struct ContextDestructionLease {
    _context: OwnedRwLockWriteGuard<()>,
}

/// Prevents creation or resharing use of an epoch while that epoch is destroyed.
#[derive(Debug)]
pub(crate) struct EpochDestructionLease {
    _epoch: OwnedRwLockWriteGuard<()>,
}

#[derive(Clone)]
pub(crate) struct SessionMaker {
    networking_manager: Arc<RwLock<GrpcNetworkingManager>>,
    context_map: Arc<RwLock<ContextMap>>,
    epoch_map: Arc<RwLock<HashMap<EpochId, EpochData>>>,
    lifecycle: LifecycleCoordinator,
    verifier: Option<Arc<AttestedVerifier>>, // optional as it's not used when there's no TLS
    rng_source: Arc<RngSource>,
}

/// The role assignment shared by all dummy contexts used in tests: four parties on localhost.
#[cfg(test)]
fn four_party_dummy_role_assignment() -> RoleAssignment<Role> {
    RoleAssignment {
        inner: HashMap::from_iter((1..=4).map(|i| {
            (
                Role::indexed_from_one(i),
                Identity::new("localhost".to_string(), 8080 + i as u16, None),
            )
        })),
    }
}

impl SessionMaker {
    pub(crate) fn new(
        networking_manager: Arc<RwLock<GrpcNetworkingManager>>,
        verifier: Option<Arc<AttestedVerifier>>,
        rng_source: Arc<RngSource>,
    ) -> Self {
        Self {
            networking_manager,
            context_map: Arc::new(RwLock::new(HashMap::new())),
            epoch_map: Arc::new(RwLock::new(HashMap::new())),
            lifecycle: LifecycleCoordinator::default(),
            verifier,
            rng_source,
        }
    }

    /// Reserves a target context and epoch for an epoch creation.
    ///
    /// When `resharing_source` is present, the lease also protects its context and epoch.
    /// The returned lease must live until the creation task finishes every persistent write.
    pub(crate) async fn try_get_epoch_creation_lease(
        &self,
        context_id: &ContextId,
        epoch_id: &EpochId,
        resharing_source: Option<(&ContextId, &EpochId)>,
    ) -> Result<EpochCreationLease, LifecycleConflict> {
        let context = self.lifecycle.context_locks.lock(context_id).await;
        let context = context
            .try_read_owned()
            .map_err(|_| LifecycleConflict::Context(*context_id))?;

        let epoch = self.lifecycle.epoch_locks.lock(epoch_id).await;
        let epoch = epoch
            .try_read_owned()
            .map_err(|_| LifecycleConflict::Epoch(*epoch_id))?;

        let resharing_source = if let Some((source_context_id, source_epoch_id)) = resharing_source
        {
            let source_context = self.lifecycle.context_locks.lock(source_context_id).await;
            let source_context = source_context
                .try_read_owned()
                .map_err(|_| LifecycleConflict::Context(*source_context_id))?;

            let source_epoch = self.lifecycle.epoch_locks.lock(source_epoch_id).await;
            let source_epoch = source_epoch
                .try_read_owned()
                .map_err(|_| LifecycleConflict::Epoch(*source_epoch_id))?;

            Some((source_context, source_epoch))
        } else {
            None
        };

        Ok(EpochCreationLease {
            _target_context: context,
            _target_epoch: epoch,
            _resharing_source: resharing_source,
        })
    }

    /// Exclusively reserve a context for destruction.
    ///
    /// The caller must retain the lease while taking the epoch snapshot, deleting every associated
    /// epoch, and deleting the context itself. Acquiring it fails while an epoch creation for this
    /// context is in flight.
    pub(crate) async fn try_get_context_destruction_lease(
        &self,
        context_id: &ContextId,
    ) -> Result<ContextDestructionLease, LifecycleConflict> {
        let context = self.lifecycle.context_locks.lock(context_id).await;
        let context = context
            .try_write_owned()
            .map_err(|_| LifecycleConflict::Context(*context_id))?;
        Ok(ContextDestructionLease { _context: context })
    }

    /// Exclusively reserve an epoch for destruction.
    ///
    /// Acquiring this lease fails while creation of the same epoch is in flight. The caller must
    /// retain it through all storage and cache deletion.
    pub(crate) async fn try_get_epoch_destruction_lease(
        &self,
        epoch_id: &EpochId,
    ) -> Result<EpochDestructionLease, LifecycleConflict> {
        let epoch = self.lifecycle.epoch_locks.lock(epoch_id).await;
        let epoch = epoch
            .try_write_owned()
            .map_err(|_| LifecycleConflict::Epoch(*epoch_id))?;
        Ok(EpochDestructionLease { _epoch: epoch })
    }

    /// Returns the number of active sessions.
    pub async fn active_sessions(&self) -> u64 {
        let reader_guard = self.networking_manager.read().await;
        reader_guard.active_session_count().await
    }

    /// Returns the number of inactive sessions.
    pub async fn inactive_sessions(&self) -> u64 {
        let reader_guard = self.networking_manager.read().await;
        reader_guard.inactive_session_count().await
    }

    /// Return the epoch Ids associated with a given context Id.
    pub async fn epochs_for_context(&self, context_id: &ContextId) -> Vec<EpochId> {
        let epoch_map = self.epoch_map.read().await;
        epoch_map
            .iter()
            .filter_map(|(epoch_id, epoch_data)| {
                (epoch_data.context_id == *context_id).then_some(*epoch_id)
            })
            .collect()
    }

    pub(crate) async fn context_count(&self) -> usize {
        self.context_map.read().await.len()
    }

    pub(crate) async fn epoch_count(&self) -> usize {
        self.epoch_map.read().await.len()
    }

    #[cfg(test)]
    pub(crate) fn empty_dummy_session(rngs: TaskRngs) -> Self {
        let networking_manager = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap(),
        ));
        Self {
            networking_manager,
            context_map: Arc::new(RwLock::new(HashMap::new())),
            epoch_map: Arc::new(RwLock::new(HashMap::new())),
            lifecycle: LifecycleCoordinator::default(),
            verifier: None,
            rng_source: Arc::new(RngSource::from_rngs(rngs)),
        }
    }

    /// Registers an extra dummy four party context (same identities and threshold as
    /// [`Self::four_party_dummy_session`]) so tests can target a context other than
    /// [`crate::consts::DEFAULT_MPC_CONTEXT`], e.g. as the destination context of a reshare.
    #[cfg(test)]
    pub(crate) async fn add_four_party_dummy_context(&self, context_id: ContextId) {
        self.add_context(
            context_id,
            Some(Role::indexed_from_one(1)),
            four_party_dummy_role_assignment(),
            HashMap::new(),
            1,
        )
        .await;
    }

    #[cfg(test)]
    pub(crate) fn four_party_dummy_session(
        prss_setup_z128: Option<PRSSSetup<ResiduePolyF4Z128>>,
        prss_setup_z64: Option<PRSSSetup<ResiduePolyF4Z64>>,
        epoch_id: &EpochId,
        rngs: TaskRngs,
    ) -> Self {
        let role_assignment = four_party_dummy_role_assignment();
        let networking_manager = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap(),
        ));

        let default_context_id = *crate::consts::DEFAULT_MPC_CONTEXT;
        let default_context = Context {
            context_id: default_context_id,
            threshold: 1,
            my_role: Some(Role::indexed_from_one(1)),
            role_assignment,
            signers: HashMap::new(),
        };

        let default_epoch = match (prss_setup_z128, prss_setup_z64) {
            (Some(z128), Some(z64)) => Some(EpochData {
                context_id: default_context_id,
                prss: PRSSSetupCombined {
                    prss_setup_z128: z128,
                    prss_setup_z64: z64,
                    num_parties: 4,
                    threshold: 1,
                },
            }),
            _ => None,
        };

        Self {
            networking_manager,
            context_map: Arc::new(RwLock::new(HashMap::from_iter([(
                default_context_id,
                default_context,
            )]))),
            epoch_map: Arc::new(RwLock::new(match default_epoch {
                Some(epoch) => HashMap::from_iter([(*epoch_id, epoch)]),
                None => HashMap::new(),
            })),
            lifecycle: LifecycleCoordinator::default(),
            verifier: None,
            rng_source: Arc::new(RngSource::from_rngs(rngs)),
        }
    }

    // Returns an health check session per context I belong to.
    async fn get_healthcheck_session_all_contexts(
        &self,
    ) -> anyhow::Result<HashMap<ContextId, HealthCheckSession<Role>>> {
        // Building a session connects to every peer, so do not hold the `context_map` guard
        // across it. While that network I/O runs, a `context_map` writer can queue. The tokio
        // lock is fair: every later read then waits behind the writer, and the writer waits for
        // this guard, so a nested read such as the one in `get_healthcheck_session` never
        // completes.
        let mut contexts = Vec::new();
        {
            let context_map_guard = self.context_map.read().await;
            for (context_id, context) in context_map_guard.iter() {
                if let Some(my_role) = context.my_role {
                    contexts.push((*context_id, my_role, context.role_assignment.clone()));
                }
            }
        }

        let nm = self.networking_manager.read().await;
        let mut health_check_sessions = HashMap::new();
        for (context_id, my_role, role_assignment) in contexts {
            health_check_sessions.insert(
                context_id,
                nm.make_healthcheck_session(role_assignment, my_role)
                    .await?,
            );
        }
        Ok(health_check_sessions)
    }

    async fn get_healthcheck_session(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<HealthCheckSession<Role>> {
        let nm = self.networking_manager.read().await;
        let role_assignment = self.get_role_assignment(context_id).await?;
        let my_role = self.my_role(context_id).await?;

        if let Some(role) = my_role {
            Ok(nm.make_healthcheck_session(role_assignment, role).await?)
        } else {
            Err(anyhow::anyhow!(
                "My role is not defined for context {}",
                context_id
            ))
        }
    }

    async fn get_role_assignment(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<RoleAssignment<Role>> {
        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;
        Ok(context_info.role_assignment.clone())
    }

    pub(crate) fn make_immutable(&self) -> ImmutableSessionMaker {
        ImmutableSessionMaker {
            inner: self.clone(),
        }
    }

    #[cfg(test)]
    async fn add_context(
        &self,
        context_id: ContextId,
        my_role: Option<Role>,
        role_assignment: RoleAssignment<Role>,
        signers: HashMap<Role, SignerAddress>,
        threshold: u8,
    ) {
        let mut context_map = self.context_map.write().await;
        context_map.insert(
            context_id,
            Context {
                context_id,
                my_role,
                role_assignment,
                signers,
                threshold,
            },
        );
    }

    /// Adds information given by [ContextInfo] struct into the session maker.
    pub(crate) async fn add_context_info(
        &self,
        my_role: Option<Role>,
        info: &ContextInfo,
    ) -> anyhow::Result<()> {
        let mut role_assignment_map = HashMap::new();
        let mut signers = HashMap::new();
        let mut ca_certs_map = HashMap::new();

        let num_nodes = info.mpc_nodes.len();
        for node in &info.mpc_nodes {
            let mpc_url = url::Url::parse(&node.external_url)
                .map_err(|e| anyhow::anyhow!("url parsing error for party: {}", e))?;
            let hostname = mpc_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host"))?;
            let port = mpc_url
                .port()
                .ok_or_else(|| anyhow::anyhow!("missing port"))?;
            // Defense-in-depth: `indexed_from_one` asserts (panics) on 0. `ContextInfo::verify`
            // normally validates this first, but guard here so a future caller can't reach it.
            let party_id = node.party_id as usize;
            if party_id < 1 || party_id > num_nodes {
                return Err(anyhow::anyhow!(
                    "party_id {} out of range 1..={} in context {}",
                    node.party_id,
                    num_nodes,
                    info.context_id()
                ));
            }
            // A duplicate (in-range) party_id would silently overwrite a prior entry, yielding
            // a role assignment with fewer parties than nodes. verify() rejects duplicates
            // upstream; reject here too so this stays safe if a caller skips verify().
            if role_assignment_map
                .insert(
                    Role::indexed_from_one(party_id),
                    Identity::new(hostname.to_string(), port, Some(node.mpc_identity.clone())),
                )
                .is_some()
            {
                return Err(anyhow::anyhow!(
                    "duplicate party_id {} in context {}",
                    node.party_id,
                    info.context_id()
                ));
            }
            let signer = node
                .ecdsa_signer_address()
                .map_err(|e| anyhow::anyhow!("{e} in context {}", info.context_id()))?;
            if let Some(signer) = signer {
                signers.insert(Role::indexed_from_one(party_id), signer);
            }

            if let Some(ca_cert) = &node.ca_cert {
                let ca_cert = x509_parser::pem::parse_x509_pem(ca_cert)
                    .map_err(|e| anyhow::anyhow!("x509 parsing error for party: {}", e))?
                    .1;
                ca_certs_map.insert(MpcIdentity(node.mpc_identity.clone()), ca_cert);
            }
        }

        let role_assignment = RoleAssignment {
            inner: role_assignment_map,
        };

        let context_id = *info.context_id();

        let mut context_map = self.context_map.write().await;
        if context_map.contains_key(&context_id) {
            tracing::error!("Refusing to replace existing MPC context {context_id}");
            anyhow::bail!("MPC context {context_id} already exists");
        }

        context_map.insert(
            context_id,
            Context {
                context_id,
                my_role,
                role_assignment,
                signers,
                threshold: info.threshold as u8,
            },
        );
        drop(context_map);

        if let Some(verifier) = &self.verifier {
            let verifier_context_id = context_id.derive_session_id()?;
            let release_pcrs = if info.pcr_values.is_empty() {
                tracing::warn!(
                    "No PCR values provided for context {}, attested TLS verification may be weakened",
                    info.context_id()
                );
                None
            } else {
                Some(info.pcr_values.iter().cloned().collect())
            };
            verifier
                .add_context(verifier_context_id, ca_certs_map, release_pcrs)
                .map_err(|e| anyhow::anyhow!("Failed to add context to verifier: {e}"))?;
        }

        Ok(())
    }

    /// Removes a context from both the TLS verifier and the session context map.
    pub(crate) async fn remove_context(&self, context_id: &ContextId) -> anyhow::Result<()> {
        if let Some(verifier) = &self.verifier {
            let verifier_context_id = context_id.derive_session_id().map_err(|e| {
                anyhow::anyhow!(
                    "Failed to derive verifier context ID for context {context_id}: {e}"
                )
            })?;
            verifier.remove_context(verifier_context_id).map_err(|e| {
                anyhow::anyhow!("Failed to remove context {context_id} from verifier: {e}")
            })?;
        }

        let mut context_map = self.context_map.write().await;
        context_map.remove(context_id);
        Ok(())
    }

    pub(crate) async fn add_epoch(&self, epoch_id: EpochId, epoch_data: EpochData) {
        let mut epoch_map = self.epoch_map.write().await;
        epoch_map.insert(epoch_id, epoch_data);
    }

    pub(crate) async fn remove_epoch(&self, epoch_id: &EpochId) {
        let mut epoch_map = self.epoch_map.write().await;
        epoch_map.remove(epoch_id);
    }

    pub(crate) async fn epoch_exists(&self, epoch_id: &EpochId) -> bool {
        let epoch_map = self.epoch_map.read().await;
        epoch_map.contains_key(epoch_id)
    }

    pub(crate) async fn context_exists(&self, context_id: &ContextId) -> bool {
        let context_map = self.context_map.read().await;
        context_map.contains_key(context_id)
    }

    pub(crate) fn reseed_rng(&self) -> Result<(), RngSourceError> {
        self.rng_source.reseed()?;

        tracing::info!("RNG Reseeded with fresh entropy");
        Ok(())
    }

    pub(crate) async fn make_base_session(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        let networking = self
            .get_networking(session_id, context_id, network_mode)
            .await;

        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(&context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;

        let parameters = SessionParameters::new(
            context_info.threshold,
            session_id,
            context_info.my_role.ok_or_else(|| {
                anyhow::anyhow!("My role is not defined for context {}", context_id)
            })?,
            context_info.role_assignment.keys().cloned().collect(),
        )?;

        let base_session =
            BaseSession::new(parameters, networking?, self.rng_source.fork_rng_128())?;
        Ok(base_session)
    }

    async fn make_small_async_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        self.make_small_session_z128(session_id, context_id, epoch_id, NetworkMode::Async)
            .await
    }

    async fn make_small_sync_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        self.make_small_session_z128(session_id, context_id, epoch_id, NetworkMode::Sync)
            .await
    }

    async fn make_small_async_session_z64(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        self.make_small_session_z64(session_id, context_id, epoch_id, NetworkMode::Async)
            .await
    }

    async fn make_small_sync_session_z64(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        self.make_small_session_z64(session_id, context_id, epoch_id, NetworkMode::Sync)
            .await
    }

    async fn make_small_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        let base_session = self
            .make_base_session(session_id, context_id, network_mode)
            .await?;

        let prss_state = {
            let epoch_map_guard = self.epoch_map.read().await;
            let prss_setup_extended = epoch_map_guard
                .get(&epoch_id)
                .ok_or_else(|| anyhow::anyhow!("Epoch ID {} not found in epoch map", epoch_id))?;
            let prss_setup = &prss_setup_extended.prss.prss_setup_z128;
            prss_setup.new_prss_session_state(session_id, base_session.my_role())?
        };

        let session = SmallSession {
            base_session,
            prss_state,
        };
        Ok(session)
    }

    async fn make_small_session_z64(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        let base_session = self
            .make_base_session(session_id, context_id, network_mode)
            .await?;

        let prss_state = {
            let epoch_map_guard = self.epoch_map.read().await;
            let prss_setup_extended = epoch_map_guard
                .get(&epoch_id)
                .ok_or_else(|| anyhow::anyhow!("Epoch ID {} not found in epoch map", epoch_id))?;
            let prss_setup = &prss_setup_extended.prss.prss_setup_z64;

            prss_setup.new_prss_session_state(session_id, base_session.my_role())?
        };

        let session = SmallSession {
            base_session,
            prss_state,
        };
        Ok(session)
    }

    pub async fn make_two_sets_session(
        &self,
        session_id: SessionId,
        context_id_set1: ContextId,
        context_id_set2: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<TwoSetsBaseSession> {
        let (session_params, role_assignment) = self
            .get_session_params_two_sets(session_id, &context_id_set1, &context_id_set2)
            .await?;

        let network = self
            .get_networking_two_sets(
                session_id,
                role_assignment,
                session_params.my_role(),
                context_id_set1,
                context_id_set2,
                network_mode,
            )
            .await?;

        TwoSetsBaseSession::new(session_params, network, self.rng_source.fork_rng_128())
    }

    async fn get_networking(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<threshold_execution::runtime::sessions::base_session::SingleSetNetworkingImpl>
    {
        let nm = self.networking_manager.read().await;

        let (role_assignment, my_role) = {
            let context_map_guard = self.context_map.read().await;
            let context_info = context_map_guard.get(&context_id).ok_or_else(|| {
                anyhow::anyhow!("Context {} not found in context map", context_id)
            })?;
            (context_info.role_assignment.clone(), context_info.my_role)
        };

        if let Some(role) = my_role {
            let networking = nm
                .make_network_session(session_id, &role_assignment, role, network_mode)
                .await?;
            tracing::debug!(
                "Getting networking for session_id={}, context_id={:?}, my_role={:?}, network_mode={:?}",
                session_id,
                context_id,
                role,
                network_mode
            );
            Ok(networking)
        } else {
            Err(anyhow::anyhow!(
                "My role is not defined for context {}",
                context_id
            ))
        }
    }

    async fn get_networking_two_sets(
        &self,
        session_id: SessionId,
        role_assignment: RoleAssignment<TwoSetsRole>,
        my_role: TwoSetsRole,
        context_id_set1: ContextId,
        context_id_set2: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<threshold_execution::runtime::sessions::base_session::TwoSetsNetworkingImpl>
    {
        let nm = self.networking_manager.read().await;
        let networking = nm
            .make_network_session(session_id, &role_assignment, my_role, network_mode)
            .await?;
        tracing::debug!(
            "Getting networking for session_id={}, context_id_1={:?}, context_id_2={:?}, my_role={:?}, network_mode={:?}",
            session_id,
            context_id_set1,
            context_id_set2,
            my_role,
            network_mode
        );
        Ok(networking)
    }

    async fn get_session_params_two_sets(
        &self,
        session_id: SessionId,
        context_id_set1: &ContextId,
        context_id_set2: &ContextId,
    ) -> anyhow::Result<(TwoSetsSessionParameters, RoleAssignment<TwoSetsRole>)> {
        let context_map_guard = self.context_map.read().await;
        let context_info_s1 = context_map_guard.get(context_id_set1).ok_or_else(|| {
            anyhow::anyhow!("Context {} not found in context map", context_id_set1)
        })?;
        let context_info_s2 = context_map_guard.get(context_id_set2).ok_or_else(|| {
            anyhow::anyhow!("Context {} not found in context map", context_id_set2)
        })?;

        let threshold = TwoSetsThreshold {
            threshold_set_1: context_info_s1.threshold,
            threshold_set_2: context_info_s2.threshold,
        };

        let my_role_both_sets = match (context_info_s1.my_role, context_info_s2.my_role) {
            (None, None) => {
                return Err(anyhow::anyhow!(
                    "Trying to get parameters for a two sets session, but I am not part of any of the two context {} ,{}",
                    context_id_set1,
                    context_id_set2
                ));
            }
            (None, Some(role)) => TwoSetsRole::OnlySet2(role),
            (Some(role), None) => TwoSetsRole::OnlySet1(role),
            (Some(role_set_1), Some(role_set_2)) => TwoSetsRole::Both(DualRole {
                role_set_1,
                role_set_2,
            }),
        };

        let role_assignment_both_sets =
            merge_two_sets_role_assignments(context_info_s1, context_info_s2)?;
        // `my_role` comes from the signer address of this node, the merge from MPC identities.
        // They disagree if one context lists my MPC identity without my signer address.
        if !role_assignment_both_sets.contains_key(&my_role_both_sets) {
            return Err(anyhow::anyhow!(
                "My role {my_role_both_sets} is not in the merged party set of contexts {context_id_set1} and {context_id_set2}: both contexts list my MPC identity, but only one lists my signer address"
            ));
        }
        let session_parameters = TwoSetsSessionParameters::new(
            threshold,
            session_id,
            my_role_both_sets,
            role_assignment_both_sets.keys().cloned().collect(),
        )?;

        Ok((session_parameters, role_assignment_both_sets))
    }

    // If the context does not exist, this returns an error.
    // If I don't belong to the context, this returns None.
    pub(crate) async fn my_identity(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<Option<Identity>> {
        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;

        Ok(context_info
            .my_role
            .and_then(|my_role| context_info.role_assignment.get(&my_role))
            .cloned())
    }

    // If the context does not exist, this returns an error.
    // If I don't belong to the context, this returns None.
    pub(crate) async fn my_role(&self, context_id: &ContextId) -> anyhow::Result<Option<Role>> {
        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;
        Ok(context_info.my_role)
    }

    pub(crate) async fn threshold(&self, context_id: &ContextId) -> anyhow::Result<u8> {
        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;
        Ok(context_info.threshold)
    }

    #[expect(dead_code)]
    pub(crate) async fn num_parties(&self, context_id: &ContextId) -> anyhow::Result<usize> {
        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;
        Ok(context_info.role_assignment.len())
    }
}

/// Merges the role assignments of the two contexts of a two-sets session.
///
/// A party of set 1 and a party of set 2 become one [`TwoSetsRole::Both`] party if they have
/// the same MPC identity. TLS authenticates the MPC identity, and the networking layer routes
/// messages by it. The URL only tells where to connect, so the merge ignores it. A merged party
/// keeps its set 2 [`Identity`], so the session connects to it at the URL of the new context.
///
/// Returns an error if the contexts disagree about a party: one MPC identity with two different
/// signer addresses, or one signer address with two different MPC identities. A party without a
/// listed signer address merges by MPC identity alone. Also returns an error if one context
/// lists an MPC identity or a signer address twice.
fn merge_two_sets_role_assignments(
    context_set1: &Context,
    context_set2: &Context,
) -> anyhow::Result<RoleAssignment<TwoSetsRole>> {
    let context_id_set1 = &context_set1.context_id;
    let context_id_set2 = &context_set2.context_id;
    // Set 1 is indexed only to reject duplicates in it.
    roles_by_mpc_identity(context_set1)?;
    roles_by_signer(context_set1)?;
    let mut set2_by_mpc_identity = roles_by_mpc_identity(context_set2)?;
    let set2_by_signer = roles_by_signer(context_set2)?;

    let mut merged = RoleAssignment::empty();
    for (role_set_1, identity_set_1) in context_set1.role_assignment.iter() {
        let mpc_identity = identity_set_1.mpc_identity();
        let signer_set_1 = context_set1.signers.get(role_set_1);
        let role_by_mpc_identity = set2_by_mpc_identity
            .get(&mpc_identity)
            .map(|(role, _)| *role);

        if let Some(signer) = signer_set_1
            && let Some(role_by_signer) = set2_by_signer.get(signer)
            && role_by_mpc_identity != Some(*role_by_signer)
        {
            let other_mpc_identity = context_set2
                .role_assignment
                .get(role_by_signer)
                .map(|identity| identity.mpc_identity().to_string())
                .unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Signer {} is party {role_set_1} with MPC identity {mpc_identity} in context {context_id_set1}, but party {role_by_signer} with MPC identity {other_mpc_identity} in context {context_id_set2}",
                signer.0
            ));
        }

        let Some((role_set_2, identity_set_2)) = set2_by_mpc_identity.remove(&mpc_identity) else {
            merged.insert(TwoSetsRole::OnlySet1(*role_set_1), identity_set_1.clone());
            continue;
        };
        if let (Some(signer_1), Some(signer_2)) =
            (signer_set_1, context_set2.signers.get(&role_set_2))
            && signer_1 != signer_2
        {
            return Err(anyhow::anyhow!(
                "MPC identity {mpc_identity} is party {role_set_1} with signer {} in context {context_id_set1}, but party {role_set_2} with signer {} in context {context_id_set2}",
                signer_1.0,
                signer_2.0
            ));
        }
        merged.insert(
            TwoSetsRole::Both(DualRole {
                role_set_1: *role_set_1,
                role_set_2,
            }),
            identity_set_2.clone(),
        );
    }

    // The set 2 parties left in the index have no MPC identity in set 1.
    for (role_set_2, identity_set_2) in set2_by_mpc_identity.into_values() {
        merged.insert(TwoSetsRole::OnlySet2(role_set_2), identity_set_2.clone());
    }
    Ok(merged)
}

/// Maps each MPC identity of `context` to the role and the network identity of its party.
///
/// Returns an error if two parties of the context have the same MPC identity.
fn roles_by_mpc_identity(
    context: &Context,
) -> anyhow::Result<HashMap<MpcIdentity, (Role, &Identity)>> {
    let mut roles = HashMap::new();
    for (role, identity) in context.role_assignment.iter() {
        if let Some((other_role, _)) = roles.insert(identity.mpc_identity(), (*role, identity)) {
            return Err(anyhow::anyhow!(
                "Parties {other_role} and {role} have the same MPC identity {} in context {}",
                identity.mpc_identity(),
                context.context_id
            ));
        }
    }
    Ok(roles)
}

/// Maps each listed signer address of `context` to the role of its party.
///
/// Returns an error if two parties of the context have the same signer address.
fn roles_by_signer(context: &Context) -> anyhow::Result<HashMap<SignerAddress, Role>> {
    let mut roles = HashMap::new();
    for (role, signer) in context.signers.iter() {
        if let Some(other_role) = roles.insert(*signer, *role) {
            return Err(anyhow::anyhow!(
                "Parties {other_role} and {role} have the same signer {} in context {}",
                signer.0,
                context.context_id
            ));
        }
    }
    Ok(roles)
}

/// This is the same as [SessionMaker] but it does not allow mutation of the inner state.
/// That is, no new contexts or epochs can be added.
///
/// Cloning this type is cheap and it is safe to share between threads.
#[derive(Clone)]
pub(crate) struct ImmutableSessionMaker {
    inner: SessionMaker,
}

impl ImmutableSessionMaker {
    /// Exclusively reserve a context while its epochs and context metadata are destroyed.
    pub(crate) async fn try_start_context_destruction(
        &self,
        context_id: &ContextId,
    ) -> Result<ContextDestructionLease, LifecycleConflict> {
        self.inner
            .try_get_context_destruction_lease(context_id)
            .await
    }

    #[expect(dead_code)]
    pub(crate) async fn context_exists(&self, context_id: &ContextId) -> bool {
        self.inner.context_exists(context_id).await
    }

    pub(crate) async fn epochs_for_context(&self, context_id: &ContextId) -> Vec<EpochId> {
        self.inner.epochs_for_context(context_id).await
    }

    pub(crate) async fn make_base_session(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        self.inner
            .make_base_session(session_id, context_id, network_mode)
            .await
    }

    pub(crate) async fn make_small_async_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        self.inner
            .make_small_async_session_z128(session_id, context_id, epoch_id)
            .await
    }

    pub(crate) async fn make_small_async_session_z64(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        self.inner
            .make_small_async_session_z64(session_id, context_id, epoch_id)
            .await
    }

    pub(crate) async fn make_small_sync_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        self.inner
            .make_small_sync_session_z128(session_id, context_id, epoch_id)
            .await
    }

    pub(crate) async fn make_small_sync_session_z64(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        self.inner
            .make_small_sync_session_z64(session_id, context_id, epoch_id)
            .await
    }

    pub(crate) async fn make_two_sets_session(
        &self,
        session_id: SessionId,
        context_id_set1: ContextId,
        context_id_set2: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<TwoSetsBaseSession> {
        self.inner
            .make_two_sets_session(session_id, context_id_set1, context_id_set2, network_mode)
            .await
    }

    /// If the context doesn't exist or I don't belong to the context,
    /// return an error .
    pub(crate) async fn my_identity(&self, context_id: &ContextId) -> anyhow::Result<Identity> {
        self.inner.my_identity(context_id).await?.ok_or_else(|| {
            anyhow::anyhow!("My identitify is not defined for context {}", context_id)
        })
    }

    /// If the context doesn't exist or I don't belong to the context,
    /// return an error .
    pub(crate) async fn my_role(&self, context_id: &ContextId) -> anyhow::Result<Role> {
        self.inner
            .my_role(context_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("My role is not defined for context {}", context_id))
    }

    pub(crate) async fn threshold(&self, context_id: &ContextId) -> anyhow::Result<u8> {
        self.inner.threshold(context_id).await
    }

    /// Returns the number of active sessions.
    pub(crate) async fn active_sessions(&self) -> u64 {
        self.inner.active_sessions().await
    }

    /// Returns the number of inactive sessions.
    pub(crate) async fn inactive_sessions(&self) -> u64 {
        self.inner.inactive_sessions().await
    }

    // Returns a health check session per context.
    pub(crate) async fn get_healthcheck_session_all_contexts(
        &self,
    ) -> anyhow::Result<HashMap<ContextId, HealthCheckSession<Role>>> {
        self.inner.get_healthcheck_session_all_contexts().await
    }

    // Returns a health check session for the given context.
    pub(crate) async fn get_healthcheck_session(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<HealthCheckSession<Role>> {
        self.inner.get_healthcheck_session(context_id).await
    }
}

/// Validates that the context exists and that the epoch belongs to that same context, then returns
/// the role of the current server in this context.
pub(crate) async fn validate_context_and_epoch(
    op_tag: &'static str,
    session_maker: &ImmutableSessionMaker,
    req_id: Option<RequestId>,
    context_id: &ContextId,
    epoch_id: &EpochId,
) -> Result<Role, MetricedError> {
    // Find the role of the current server and validate the context exists
    let my_role = session_maker
        .my_role(context_id)
        .await
        .map_err(|e| MetricedError::new(op_tag, req_id, e, Code::NotFound))?;

    let context_epochs = session_maker.epochs_for_context(context_id).await;
    if !context_epochs.contains(epoch_id) {
        let known_epochs = context_epochs
            .iter()
            .map(|epoch| epoch.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(MetricedError::new(
            op_tag,
            req_id,
            anyhow::anyhow!(
                "Epoch {epoch_id} not found for context {context_id}, which currently has epochs [{known_epochs}]"
            ),
            Code::NotFound,
        ));
    }
    Ok(my_role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::engine::{
        context::{NodeInfo, SchemeDigests, SoftwareVersion},
        threshold::service::epoch_manager::tests::dummy_epoch_data,
    };
    use observability::metrics_names::OP_CRS_GEN_REQUEST;
    use std::time::Duration;
    use tokio_rustls::rustls::{
        client::danger::ServerCertVerifier,
        crypto::aws_lc_rs::default_provider,
        pki_types::{CertificateDer, ServerName, UnixTime},
        server::danger::ClientCertVerifier,
    };

    /// Sunshine: one health check session per context that has a role for this party.
    #[tokio::test]
    async fn healthcheck_sessions_cover_contexts_with_my_role() {
        let session_maker = SessionMaker::four_party_dummy_session(
            None,
            None,
            &EpochId::new_random(&mut AesRng::seed_from_u64(5)),
            TaskRngs::insecure_seed_from_u64(6),
        );
        let sessions = session_maker
            .get_healthcheck_session_all_contexts()
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        let session = sessions.get(&*crate::consts::DEFAULT_MPC_CONTEXT).unwrap();
        assert_eq!(session.get_num_parties(), 4);
    }

    /// A context change while the health check sessions are built must not deadlock. The test
    /// polls both futures by hand, so the order does not depend on timing. It holds the networking
    /// manager, so that the first poll of the health check reads `context_map` and then waits for
    /// the networking manager. A context change must then complete in one poll, which is only
    /// possible if the health check holds no `context_map` guard while it waits.
    #[tokio::test]
    async fn healthcheck_sessions_do_not_block_a_context_change() {
        let mut rng = AesRng::seed_from_u64(7);
        let session_maker = SessionMaker::four_party_dummy_session(
            None,
            None,
            &EpochId::new_random(&mut rng),
            TaskRngs::insecure_seed_from_u64(8),
        );
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let networking_guard = session_maker.networking_manager.write().await;

        let mut health_check = std::pin::pin!(session_maker.get_healthcheck_session_all_contexts());
        assert!(
            health_check.as_mut().poll(&mut cx).is_pending(),
            "the health check must wait for the networking manager"
        );

        let new_context = ContextId::new_random(&mut rng);
        let mut context_change =
            std::pin::pin!(session_maker.add_four_party_dummy_context(new_context));
        assert!(
            context_change.as_mut().poll(&mut cx).is_ready(),
            "the context change must not wait for the health check"
        );

        drop(networking_guard);
        let sessions = tokio::time::timeout(Duration::from_secs(5), health_check)
            .await
            .expect("the health check must finish once the networking manager is free")
            .unwrap();
        assert!(sessions.contains_key(&*crate::consts::DEFAULT_MPC_CONTEXT));
    }

    /// Sunshine: `epochs_for_context` returns exactly the epochs whose `EpochData` carries the
    /// requested context ID, and excludes epochs belonging to other contexts.
    #[tokio::test]
    async fn epochs_for_context_filters_by_context() {
        let mut rng = AesRng::seed_from_u64(1);
        let session_maker = SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(2));

        let context_a = ContextId::new_random(&mut rng);
        let context_b = ContextId::new_random(&mut rng);

        // Two epochs under context A, one under context B.
        let epoch_a1 = EpochId::new_random(&mut rng);
        let epoch_a2 = EpochId::new_random(&mut rng);
        let epoch_b = EpochId::new_random(&mut rng);

        session_maker
            .add_epoch(epoch_a1, dummy_epoch_data(context_a))
            .await;
        session_maker
            .add_epoch(epoch_a2, dummy_epoch_data(context_a))
            .await;
        session_maker
            .add_epoch(epoch_b, dummy_epoch_data(context_b))
            .await;

        let for_a: std::collections::HashSet<EpochId> = session_maker
            .epochs_for_context(&context_a)
            .await
            .into_iter()
            .collect();
        let expected: std::collections::HashSet<EpochId> =
            [epoch_a1, epoch_a2].into_iter().collect();
        assert_eq!(for_a, expected, "context A must map to exactly its epochs");

        let for_b = session_maker.epochs_for_context(&context_b).await;
        assert_eq!(
            for_b,
            vec![epoch_b],
            "context B must map to exactly its single epoch"
        );
    }

    /// Negative: an unknown context (or one with no epochs) yields an empty result rather than an
    /// error or spurious epochs.
    #[tokio::test]
    async fn epochs_for_context_unknown_context_is_empty() {
        let mut rng = AesRng::seed_from_u64(3);
        let session_maker = SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(4));

        let known_context = ContextId::new_random(&mut rng);
        session_maker
            .add_epoch(
                EpochId::new_random(&mut rng),
                dummy_epoch_data(known_context),
            )
            .await;

        let unknown_context = ContextId::new_random(&mut rng);
        assert!(
            session_maker
                .epochs_for_context(&unknown_context)
                .await
                .is_empty(),
            "a context with no registered epochs must yield an empty vector"
        );

        // An entirely empty session maker also returns empty.
        let empty_session = SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(5));
        assert!(
            empty_session
                .epochs_for_context(&known_context)
                .await
                .is_empty()
        );
    }

    /// Register a context that this node belongs to.
    async fn add_member_context(session_maker: &SessionMaker, context_id: ContextId) {
        session_maker
            .add_context(
                context_id,
                Some(Role::indexed_from_one(1)),
                RoleAssignment::empty(),
                HashMap::new(),
                1,
            )
            .await;
    }

    /// Sunshine: an epoch registered under the requested context validates, and the call returns
    /// the role of this node in that context.
    #[tokio::test]
    async fn validate_context_and_epoch_accepts_own_epoch() {
        let mut rng = AesRng::seed_from_u64(200);
        let session_maker =
            SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(201));

        let context_id = ContextId::new_random(&mut rng);
        let epoch_id = EpochId::new_random(&mut rng);
        add_member_context(&session_maker, context_id).await;
        session_maker
            .add_epoch(epoch_id, dummy_epoch_data(context_id))
            .await;

        let my_role = validate_context_and_epoch(
            OP_CRS_GEN_REQUEST,
            &session_maker.make_immutable(),
            None,
            &context_id,
            &epoch_id,
        )
        .await
        .unwrap();
        assert_eq!(my_role, Role::indexed_from_one(1));
    }

    /// Negative: an epoch that belongs to another context must not validate against the requested
    /// context, even though the epoch map holds it.
    #[tokio::test]
    async fn validate_context_and_epoch_rejects_epoch_of_other_context() {
        let mut rng = AesRng::seed_from_u64(202);
        let session_maker =
            SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(203));

        let context_a = ContextId::new_random(&mut rng);
        let context_b = ContextId::new_random(&mut rng);
        let epoch_a = EpochId::new_random(&mut rng);
        let epoch_b = EpochId::new_random(&mut rng);

        add_member_context(&session_maker, context_a).await;
        add_member_context(&session_maker, context_b).await;
        session_maker
            .add_epoch(epoch_a, dummy_epoch_data(context_a))
            .await;
        session_maker
            .add_epoch(epoch_b, dummy_epoch_data(context_b))
            .await;

        // A check on epoch existence alone accepts the mismatched pair below.
        assert!(session_maker.epoch_exists(&epoch_b).await);

        let err = validate_context_and_epoch(
            OP_CRS_GEN_REQUEST,
            &session_maker.make_immutable(),
            None,
            &context_a,
            &epoch_b,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        // The error lists the epochs of the requested context, not the epoch of the other context.
        let message = err.to_string();
        assert!(
            message.contains(&epoch_a.to_string()),
            "the error must name the epochs of context A: {message}"
        );
        err.defuse();
    }

    /// An epoch creation is visible to lifecycle coordination before it is registered in
    /// `epoch_map`, so neither its context nor its epoch can be destroyed in that window.
    #[tokio::test]
    async fn epoch_creation_lease_blocks_matching_destruction_only() {
        let mut rng = AesRng::seed_from_u64(6);
        let session_maker = SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(7));
        let context_id = ContextId::new_random(&mut rng);
        let epoch_id = EpochId::new_random(&mut rng);
        let endpoint_session_maker = session_maker.make_immutable();

        let creation = session_maker
            .try_get_epoch_creation_lease(&context_id, &epoch_id, None)
            .await
            .unwrap();

        assert_eq!(
            endpoint_session_maker
                .try_start_context_destruction(&context_id)
                .await
                .unwrap_err(),
            LifecycleConflict::Context(context_id)
        );
        assert_eq!(
            session_maker
                .try_get_epoch_destruction_lease(&epoch_id)
                .await
                .unwrap_err(),
            LifecycleConflict::Epoch(epoch_id)
        );

        // Unrelated lifecycle operations remain independent.
        let other_context_id = ContextId::new_random(&mut rng);
        let other_epoch_id = EpochId::new_random(&mut rng);
        endpoint_session_maker
            .try_start_context_destruction(&other_context_id)
            .await
            .unwrap();
        session_maker
            .try_get_epoch_destruction_lease(&other_epoch_id)
            .await
            .unwrap();

        drop(creation);
        endpoint_session_maker
            .try_start_context_destruction(&context_id)
            .await
            .unwrap();
        session_maker
            .try_get_epoch_destruction_lease(&epoch_id)
            .await
            .unwrap();
    }

    /// An epoch creation lease keeps both parts of its resharing source available until the
    /// creation task releases the lease.
    #[tokio::test]
    async fn epoch_creation_lease_protects_resharing_source() {
        let mut rng = AesRng::seed_from_u64(100);
        let session_maker =
            SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(101));
        let source_context_id = ContextId::new_random(&mut rng);
        let source_epoch_id = EpochId::new_random(&mut rng);
        let new_context_id = ContextId::new_random(&mut rng);
        let new_epoch_id = EpochId::new_random(&mut rng);
        let endpoint_session_maker = session_maker.make_immutable();

        let creation = session_maker
            .try_get_epoch_creation_lease(
                &new_context_id,
                &new_epoch_id,
                Some((&source_context_id, &source_epoch_id)),
            )
            .await
            .unwrap();

        assert_eq!(
            endpoint_session_maker
                .try_start_context_destruction(&source_context_id)
                .await
                .unwrap_err(),
            LifecycleConflict::Context(source_context_id)
        );
        assert_eq!(
            session_maker
                .try_get_epoch_destruction_lease(&source_epoch_id)
                .await
                .unwrap_err(),
            LifecycleConflict::Epoch(source_epoch_id)
        );

        drop(creation);
        endpoint_session_maker
            .try_start_context_destruction(&source_context_id)
            .await
            .unwrap();
        session_maker
            .try_get_epoch_destruction_lease(&source_epoch_id)
            .await
            .unwrap();
    }

    /// Whichever destructive operation acquires its exclusive lease first prevents a conflicting
    /// epoch creation from beginning until that lease is released.
    #[tokio::test]
    async fn destruction_leases_block_epoch_creation_until_drop() {
        let mut rng = AesRng::seed_from_u64(8);
        let session_maker = SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(9));
        let context_id = ContextId::new_random(&mut rng);
        let epoch_id = EpochId::new_random(&mut rng);
        let source_context_id = ContextId::new_random(&mut rng);
        let source_epoch_id = EpochId::new_random(&mut rng);

        let context_destruction = session_maker
            .try_get_context_destruction_lease(&context_id)
            .await
            .unwrap();
        assert_eq!(
            session_maker
                .try_get_epoch_creation_lease(&context_id, &epoch_id, None)
                .await
                .unwrap_err(),
            LifecycleConflict::Context(context_id)
        );
        drop(context_destruction);

        let epoch_destruction = session_maker
            .try_get_epoch_destruction_lease(&epoch_id)
            .await
            .unwrap();
        assert_eq!(
            session_maker
                .try_get_epoch_creation_lease(&context_id, &epoch_id, None)
                .await
                .unwrap_err(),
            LifecycleConflict::Epoch(epoch_id)
        );
        drop(epoch_destruction);

        session_maker
            .try_get_epoch_creation_lease(&context_id, &epoch_id, None)
            .await
            .unwrap();

        let source_context_destruction = session_maker
            .try_get_context_destruction_lease(&source_context_id)
            .await
            .unwrap();
        assert_eq!(
            session_maker
                .try_get_epoch_creation_lease(
                    &context_id,
                    &epoch_id,
                    Some((&source_context_id, &source_epoch_id)),
                )
                .await
                .unwrap_err(),
            LifecycleConflict::Context(source_context_id)
        );
        drop(source_context_destruction);

        let source_epoch_destruction = session_maker
            .try_get_epoch_destruction_lease(&source_epoch_id)
            .await
            .unwrap();
        assert_eq!(
            session_maker
                .try_get_epoch_creation_lease(
                    &context_id,
                    &epoch_id,
                    Some((&source_context_id, &source_epoch_id)),
                )
                .await
                .unwrap_err(),
            LifecycleConflict::Epoch(source_epoch_id)
        );
        drop(source_epoch_destruction);

        session_maker
            .try_get_epoch_creation_lease(
                &context_id,
                &epoch_id,
                Some((&source_context_id, &source_epoch_id)),
            )
            .await
            .unwrap();
    }

    fn session_maker_with_attested_verifier() -> (SessionMaker, Arc<AttestedVerifier>) {
        _ = default_provider().install_default();
        let verifier = Arc::new(
            AttestedVerifier::new(
                None,
                false,
                #[cfg(feature = "insecure")]
                true,
            )
            .unwrap(),
        );
        let networking_manager = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap(),
        ));
        let session_maker = SessionMaker::new(
            networking_manager,
            Some(Arc::clone(&verifier)),
            Arc::new(RngSource::from_rngs(TaskRngs::insecure_seed_from_u64(6))),
        );

        (session_maker, verifier)
    }

    fn context_with_ca(
        identity: &str,
        certificate_pem: Vec<u8>,
        context_id: ContextId,
        pcr_values: Vec<threshold_networking::tls::ReleasePCRValues>,
    ) -> ContextInfo {
        ContextInfo {
            mpc_nodes: vec![NodeInfo {
                mpc_identity: identity.to_string(),
                party_id: 1,
                external_url: format!("https://{identity}:8443"),
                ca_cert: Some(certificate_pem),
                public_storage_url: String::new(),
                public_storage_prefix: None,
                extra_signer_addresses: vec![],
                scheme_digests: SchemeDigests::new(),
            }],
            context_id,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
            pcr_values,
        }
    }

    fn certificate_der(certificate_pem: &[u8]) -> Vec<u8> {
        x509_parser::pem::parse_x509_pem(certificate_pem)
            .unwrap()
            .1
            .contents
    }

    #[tokio::test]
    async fn remove_context_updates_attested_verifier_references() {
        let (session_maker, verifier) = session_maker_with_attested_verifier();

        let identity = "shared.example.com";
        let (ca_pem, pcr_values) =
            threshold_networking::tls::generate_mock_tls_cert_with_attestation(identity)
                .await
                .unwrap();
        let certificate_der = certificate_der(&ca_pem.contents);
        let mut rng = AesRng::seed_from_u64(7);
        let context_a = ContextId::new_random(&mut rng);
        let context_b = ContextId::new_random(&mut rng);
        session_maker
            .add_context_info(
                None,
                &context_with_ca(
                    identity,
                    ca_pem.contents.clone(),
                    context_a,
                    vec![pcr_values.clone()],
                ),
            )
            .await
            .unwrap();
        session_maker
            .add_context_info(
                None,
                &context_with_ca(identity, ca_pem.contents, context_b, vec![pcr_values]),
            )
            .await
            .unwrap();

        let server_name = ServerName::try_from(identity).unwrap();
        let verify_server = || {
            verifier.verify_server_cert(
                &CertificateDer::from_slice(&certificate_der),
                &[],
                &server_name,
                &[],
                UnixTime::now(),
            )
        };
        let verify_client = || {
            verifier.verify_client_cert(
                &CertificateDer::from_slice(&certificate_der),
                &[],
                UnixTime::now(),
            )
        };
        assert!(session_maker.context_exists(&context_a).await);
        assert!(session_maker.context_exists(&context_b).await);
        assert!(verify_server().is_ok());
        assert!(verify_client().is_ok());

        session_maker.remove_context(&context_a).await.unwrap();
        assert!(!session_maker.context_exists(&context_a).await);
        assert!(session_maker.context_exists(&context_b).await);
        assert!(verify_server().is_ok());
        assert!(verify_client().is_ok());

        session_maker.remove_context(&context_b).await.unwrap();
        assert!(!session_maker.context_exists(&context_b).await);
        assert!(verify_server().is_err());
        assert!(verify_client().is_err());
    }

    #[tokio::test]
    async fn remove_context_removes_only_its_attested_verifier_root() {
        let (session_maker, verifier) = session_maker_with_attested_verifier();
        let identity = "rotated.example.com";
        let (ca_pem_a, pcr_values_a) =
            threshold_networking::tls::generate_mock_tls_cert_with_attestation(identity)
                .await
                .unwrap();
        let (ca_pem_b, pcr_values_b) =
            threshold_networking::tls::generate_mock_tls_cert_with_attestation(identity)
                .await
                .unwrap();
        let certificate_der_a = certificate_der(&ca_pem_a.contents);
        let certificate_der_b = certificate_der(&ca_pem_b.contents);
        let mut rng = AesRng::seed_from_u64(10);
        let context_a = ContextId::new_random(&mut rng);
        let context_b = ContextId::new_random(&mut rng);

        session_maker
            .add_context_info(
                None,
                &context_with_ca(identity, ca_pem_a.contents, context_a, vec![pcr_values_a]),
            )
            .await
            .unwrap();
        session_maker
            .add_context_info(
                None,
                &context_with_ca(identity, ca_pem_b.contents, context_b, vec![pcr_values_b]),
            )
            .await
            .unwrap();

        let server_name = ServerName::try_from(identity).unwrap();
        let verify_server = |certificate: &[u8]| {
            verifier.verify_server_cert(
                &CertificateDer::from_slice(certificate),
                &[],
                &server_name,
                &[],
                UnixTime::now(),
            )
        };
        let verify_client = |certificate: &[u8]| {
            verifier.verify_client_cert(
                &CertificateDer::from_slice(certificate),
                &[],
                UnixTime::now(),
            )
        };
        assert!(session_maker.context_exists(&context_a).await);
        assert!(session_maker.context_exists(&context_b).await);
        assert!(verify_server(&certificate_der_a).is_ok());
        assert!(verify_server(&certificate_der_b).is_ok());
        assert!(verify_client(&certificate_der_a).is_ok());
        assert!(verify_client(&certificate_der_b).is_ok());

        session_maker.remove_context(&context_a).await.unwrap();
        assert!(!session_maker.context_exists(&context_a).await);
        assert!(session_maker.context_exists(&context_b).await);
        assert!(verify_server(&certificate_der_a).is_err());
        assert!(verify_client(&certificate_der_a).is_err());
        assert!(verify_server(&certificate_der_b).is_ok());
        assert!(verify_client(&certificate_der_b).is_ok());

        session_maker.remove_context(&context_b).await.unwrap();
        assert!(!session_maker.context_exists(&context_b).await);
        assert!(verify_server(&certificate_der_b).is_err());
        assert!(verify_client(&certificate_der_b).is_err());
    }

    #[tokio::test]
    async fn duplicate_context_is_rejected_without_replacing_its_verifier_root() {
        let (session_maker, verifier) = session_maker_with_attested_verifier();
        let identity = "duplicate.example.com";
        let (ca_pem_a, pcr_values_a) =
            threshold_networking::tls::generate_mock_tls_cert_with_attestation(identity)
                .await
                .unwrap();
        let (ca_pem_b, pcr_values_b) =
            threshold_networking::tls::generate_mock_tls_cert_with_attestation(identity)
                .await
                .unwrap();
        let certificate_der_a = certificate_der(&ca_pem_a.contents);
        let certificate_der_b = certificate_der(&ca_pem_b.contents);
        let mut rng = AesRng::seed_from_u64(11);
        let context_id = ContextId::new_random(&mut rng);

        session_maker
            .add_context_info(
                None,
                &context_with_ca(identity, ca_pem_a.contents, context_id, vec![pcr_values_a]),
            )
            .await
            .unwrap();
        session_maker
            .add_context_info(
                None,
                &context_with_ca(identity, ca_pem_b.contents, context_id, vec![pcr_values_b]),
            )
            .await
            .unwrap_err();

        let server_name = ServerName::try_from(identity).unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from_slice(&certificate_der_a),
                    &[],
                    &server_name,
                    &[],
                    UnixTime::now(),
                )
                .is_ok()
        );
        assert!(
            verifier
                .verify_client_cert(
                    &CertificateDer::from_slice(&certificate_der_a),
                    &[],
                    UnixTime::now(),
                )
                .is_ok()
        );
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from_slice(&certificate_der_b),
                    &[],
                    &server_name,
                    &[],
                    UnixTime::now(),
                )
                .is_err()
        );
        assert!(
            verifier
                .verify_client_cert(
                    &CertificateDer::from_slice(&certificate_der_b),
                    &[],
                    UnixTime::now(),
                )
                .is_err()
        );
        assert_eq!(session_maker.context_count().await, 1);
    }

    /// One node of a test context for the two-sets merge.
    struct TestNode {
        mpc_identity: String,
        host: String,
        port: u16,
        signer: Option<SignerAddress>,
    }

    fn test_signer(byte: u8) -> SignerAddress {
        SignerAddress(alloy_primitives::Address::repeat_byte(byte))
    }

    /// Node `i` with MPC identity `node-{i}`, host `node-{i}{host_suffix}`, port 50001 and the
    /// signer `test_signer(i)`.
    fn test_node(i: u8, host_suffix: &str) -> TestNode {
        TestNode {
            mpc_identity: format!("node-{i}"),
            host: format!("node-{i}{host_suffix}"),
            port: 50001,
            signer: Some(test_signer(i)),
        }
    }

    fn four_test_nodes(host_suffix: &str) -> Vec<TestNode> {
        (1..=4).map(|i| test_node(i, host_suffix)).collect()
    }

    /// Registers a threshold 1 context through [`SessionMaker::add_context_info`], in which
    /// party `i` (one-based) is `nodes[i - 1]`.
    async fn add_test_context(
        session_maker: &SessionMaker,
        context_id: ContextId,
        my_role: Option<usize>,
        nodes: &[TestNode],
    ) {
        let context = ContextInfo {
            mpc_nodes: nodes
                .iter()
                .enumerate()
                .map(|(i, node)| NodeInfo {
                    mpc_identity: node.mpc_identity.clone(),
                    party_id: i as u32 + 1,
                    external_url: format!("http://{}:{}", node.host, node.port),
                    ca_cert: None,
                    public_storage_url: String::new(),
                    public_storage_prefix: None,
                    extra_signer_addresses: vec![],
                    scheme_digests: node
                        .signer
                        .map(SchemeDigests::from_ecdsa_address)
                        .unwrap_or_default(),
                })
                .collect(),
            context_id,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 1,
            pcr_values: vec![],
        };
        session_maker
            .add_context_info(my_role.map(Role::indexed_from_one), &context)
            .await
            .unwrap();
    }

    /// Registers `set1` and `set2` as two contexts and builds the two-sets session parameters.
    async fn two_sets_params(
        my_role_set1: Option<usize>,
        set1: &[TestNode],
        my_role_set2: Option<usize>,
        set2: &[TestNode],
    ) -> anyhow::Result<(TwoSetsSessionParameters, RoleAssignment<TwoSetsRole>)> {
        let mut rng = AesRng::seed_from_u64(300);
        let session_maker =
            SessionMaker::empty_dummy_session(TaskRngs::insecure_seed_from_u64(301));
        let context_set1 = ContextId::new_random(&mut rng);
        let context_set2 = ContextId::new_random(&mut rng);
        add_test_context(&session_maker, context_set1, my_role_set1, set1).await;
        add_test_context(&session_maker, context_set2, my_role_set2, set2).await;
        session_maker
            .get_session_params_two_sets(SessionId::from(1u128), &context_set1, &context_set2)
            .await
    }

    /// Same as [`two_sets_params`], but expects an error and returns its message.
    async fn two_sets_error(
        my_role_set1: Option<usize>,
        set1: &[TestNode],
        my_role_set2: Option<usize>,
        set2: &[TestNode],
    ) -> String {
        match two_sets_params(my_role_set1, set1, my_role_set2, set2).await {
            Ok(_) => panic!("building the two-sets session parameters must fail"),
            Err(e) => e.to_string(),
        }
    }

    fn both(role_set_1: usize, role_set_2: usize) -> TwoSetsRole {
        TwoSetsRole::Both(DualRole {
            role_set_1: Role::indexed_from_one(role_set_1),
            role_set_2: Role::indexed_from_one(role_set_2),
        })
    }

    fn assert_unique_mpc_identities(role_assignment: &RoleAssignment<TwoSetsRole>) {
        let mpc_identities: HashSet<_> = role_assignment
            .iter()
            .map(|(_, identity)| identity.mpc_identity())
            .collect();
        assert_eq!(mpc_identities.len(), role_assignment.len());
    }

    /// Sunshine: parties with the same MPC identity and signer merge even though their host and
    /// port differ, and the merged party uses the set 2 URL.
    #[tokio::test]
    async fn two_sets_merge_ignores_url() {
        let set1 = four_test_nodes("");
        let mut set2 = four_test_nodes(".kms.svc.cluster.local");
        set2[3].port = 50002;

        let (params, role_assignment) = two_sets_params(Some(1), &set1, Some(1), &set2)
            .await
            .unwrap();

        assert_eq!(params.my_role(), both(1, 1));
        assert_eq!(role_assignment.len(), 4);
        for i in 1..=4 {
            let identity = role_assignment.get(&both(i, i)).unwrap();
            assert_eq!(
                identity.hostname(),
                format!("node-{i}.kms.svc.cluster.local")
            );
        }
        assert_eq!(role_assignment.get(&both(4, 4)).unwrap().port(), 50002);
    }

    /// Sunshine: a party can have another role in set 2 than in set 1. The merge pairs the two
    /// roles by MPC identity, and the merged party uses the set 2 URL.
    #[tokio::test]
    async fn two_sets_merge_reordered_roles() {
        let set1 = four_test_nodes("");
        let mut set2 = four_test_nodes(".kms.svc.cluster.local");
        set2.reverse();

        let (params, role_assignment) = two_sets_params(Some(1), &set1, Some(4), &set2)
            .await
            .unwrap();

        assert_eq!(params.my_role(), both(1, 4));
        assert_eq!(role_assignment.len(), 4);
        for i in 1..=4 {
            let identity = role_assignment.get(&both(i, 5 - i)).unwrap();
            assert_eq!(identity.mpc_identity(), MpcIdentity(format!("node-{i}")));
            assert_eq!(
                identity.hostname(),
                format!("node-{i}.kms.svc.cluster.local")
            );
        }
    }

    /// Sunshine: a context that lists only this node's signer, as the default context built
    /// from the peer list does, merges with a context that lists every signer.
    #[tokio::test]
    async fn two_sets_merge_by_mpc_identity_when_signers_are_missing() {
        let mut set1 = four_test_nodes("");
        for node in &mut set1[1..] {
            node.signer = None;
        }
        let set2 = four_test_nodes(".kms.svc.cluster.local");

        let (params, role_assignment) = two_sets_params(Some(1), &set1, Some(1), &set2)
            .await
            .unwrap();

        assert_eq!(params.my_role(), both(1, 1));
        for i in 1..=4 {
            assert!(role_assignment.contains_key(&both(i, i)));
        }
    }

    /// Sunshine: a node with a new signer and a new MPC identity is a new party. The old party
    /// stays in set 1 only and the new party is in set 2 only.
    #[tokio::test]
    async fn two_sets_merge_new_signer_is_new_party() {
        let set1 = four_test_nodes("");
        let mut set2 = four_test_nodes("");
        set2[3] = test_node(5, "");

        let (params, role_assignment) = two_sets_params(Some(1), &set1, Some(1), &set2)
            .await
            .unwrap();

        assert_eq!(params.my_role(), both(1, 1));
        assert_eq!(role_assignment.len(), 5);
        for i in 1..=3 {
            assert!(role_assignment.contains_key(&both(i, i)));
        }
        let old_party = TwoSetsRole::OnlySet1(Role::indexed_from_one(4));
        let new_party = TwoSetsRole::OnlySet2(Role::indexed_from_one(4));
        assert_eq!(
            role_assignment.get(&old_party).unwrap().mpc_identity(),
            MpcIdentity("node-4".to_string())
        );
        assert_eq!(
            role_assignment.get(&new_party).unwrap().mpc_identity(),
            MpcIdentity("node-5".to_string())
        );
        assert_unique_mpc_identities(&role_assignment);
    }

    /// Sunshine: two sets without a common MPC identity or signer do not merge any party.
    #[tokio::test]
    async fn two_sets_merge_disjoint_sets() {
        let set1 = four_test_nodes("");
        let set2: Vec<_> = (5..=8).map(|i| test_node(i, "")).collect();

        let (params, role_assignment) = two_sets_params(Some(1), &set1, None, &set2).await.unwrap();

        assert_eq!(
            params.my_role(),
            TwoSetsRole::OnlySet1(Role::indexed_from_one(1))
        );
        assert_eq!(role_assignment.len(), 8);
        for i in 1..=4 {
            assert!(
                role_assignment.contains_key(&TwoSetsRole::OnlySet1(Role::indexed_from_one(i)))
            );
            assert!(
                role_assignment.contains_key(&TwoSetsRole::OnlySet2(Role::indexed_from_one(i)))
            );
        }
        assert_unique_mpc_identities(&role_assignment);
    }

    /// Negative: one MPC identity with two different signers is rejected.
    #[tokio::test]
    async fn two_sets_merge_rejects_mpc_identity_with_other_signer() {
        let set1 = four_test_nodes("");
        let mut set2 = four_test_nodes("");
        set2[1].signer = Some(test_signer(9));

        let err = two_sets_error(Some(1), &set1, Some(1), &set2).await;

        assert!(err.contains("MPC identity node-2"), "{err}");
        assert!(err.contains(&test_signer(9).0.to_string()), "{err}");
    }

    /// Negative: one signer with two different MPC identities is rejected.
    #[tokio::test]
    async fn two_sets_merge_rejects_signer_with_other_mpc_identity() {
        let set1 = four_test_nodes("");
        let mut set2 = four_test_nodes("");
        set2[1].mpc_identity = "node-2-renamed".to_string();

        let err = two_sets_error(Some(1), &set1, Some(1), &set2).await;

        assert!(err.contains(&test_signer(2).0.to_string()), "{err}");
        assert!(err.contains("node-2-renamed"), "{err}");
    }

    /// Negative: a context that lists one MPC identity twice is rejected.
    #[tokio::test]
    async fn two_sets_merge_rejects_duplicate_mpc_identity() {
        let set1 = four_test_nodes("");
        let mut set2 = four_test_nodes("");
        set2[3].mpc_identity = "node-3".to_string();

        let err = two_sets_error(Some(1), &set1, Some(1), &set2).await;

        assert!(err.contains("same MPC identity node-3"), "{err}");
    }

    /// Negative: a context that lists one signer twice is rejected.
    #[tokio::test]
    async fn two_sets_merge_rejects_duplicate_signer() {
        let mut set1 = four_test_nodes("");
        set1[3].signer = Some(test_signer(3));
        let set2 = four_test_nodes("");

        let err = two_sets_error(Some(1), &set1, Some(1), &set2).await;

        assert!(err.contains("same signer"), "{err}");
    }

    /// Negative: if set 2 lists this node's MPC identity without its signer, this node is in
    /// set 1 only by signer but merged by MPC identity, and the parameters are rejected.
    #[tokio::test]
    async fn two_sets_merge_rejects_my_mpc_identity_without_my_signer() {
        let set1 = four_test_nodes("");
        let mut set2 = four_test_nodes("");
        set2[0].signer = None;

        let err = two_sets_error(Some(1), &set1, None, &set2).await;

        assert!(err.contains("only one lists my signer address"), "{err}");
    }
}
