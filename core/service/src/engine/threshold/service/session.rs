// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

// === External Crates ===
use kms_grpc::identifiers::ContextId;
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        runtime::{
            party::{Identity, Role, RoleAssignment},
            session::{BaseSession, SessionParameters, SmallSession},
        },
        small_execution::prss::{DerivePRSSState, PRSSSetup},
    },
    networking::{grpc::GrpcNetworkingManager, health_check::HealthCheckSession, NetworkMode},
    session_id::SessionId,
    thread_handles::spawn_compute_bound,
};
use tokio::sync::RwLock;

// === Internal Crate ===
use crate::{engine::base::BaseKmsStruct, some_or_tonic_abort};

const ERR_SESSION_NOT_INITIALIZED: &str = "SessionPreparer is not initialized";

/// This is a singleton for managing session preparers.
/// Essentially keeping a map of `RequestId` (which is the context ID) to `SessionPreparer`.
///
/// This data structure should only be used by the Init GRPC endpoint.
/// The other GRPC endpoints that use session should use `SessionPreparerGetter`.
pub(crate) struct SessionPreparerManager {
    inner: SessionPreparerGetter,
}

impl SessionPreparerManager {
    /// Creates a new `SessionPreparerManager`.
    pub(crate) fn empty(name: String) -> Self {
        Self {
            inner: SessionPreparerGetter {
                session_preparer: Arc::new(RwLock::new(HashMap::new())),
                name,
            },
        }
    }

    /// Make a getter that cannot modify the manager.
    pub(crate) fn make_getter(&self) -> SessionPreparerGetter {
        SessionPreparerGetter {
            session_preparer: self.inner.session_preparer.clone(),
            name: self.inner.name.clone(),
        }
    }

    /// Returns a new instance of the session preparer for the given context ID.
    pub(crate) async fn get(&self, context_id: &ContextId) -> anyhow::Result<SessionPreparer> {
        self.inner.get(context_id).await
    }

    /// Inserts a new session preparer into the manager.
    pub(crate) async fn insert(&self, context_id: ContextId, session_preparer: SessionPreparer) {
        self.inner.insert(context_id, session_preparer).await
    }

    #[cfg(test)]
    pub(crate) fn new_test_session() -> Self {
        SessionPreparerManager::empty(Role::indexed_from_one(1).to_string())
    }
}

/// Getter for the session preparer.
///
/// Unlike [SessionPreparer], we are allowed to clone this type
/// as it's inside an Arc and to get the actual [SessionPreparer] we
/// must call [SessionPreparerGetter::get] which will return a new instance
/// that does not have a cloned Rng state.
#[derive(Clone)]
pub struct SessionPreparerGetter {
    session_preparer: Arc<RwLock<HashMap<ContextId, SessionPreparer>>>,
    name: String,
}

impl SessionPreparerGetter {
    /// Returns a new instance of the session preparer for the given context ID.
    pub async fn get(&self, context_id: &ContextId) -> anyhow::Result<SessionPreparer> {
        let guarded_session_preparer = self.session_preparer.read().await;
        match guarded_session_preparer.get(context_id) {
            Some(session_preparer) => Ok(session_preparer.new_instance().await),
            None => Err(anyhow::anyhow!(
                "No session preparer found for context ID: {}",
                context_id
            )),
        }
    }

    // Returns the an health check session per context.
    pub async fn get_healthcheck_session_all_contexts(
        &self,
    ) -> anyhow::Result<HashMap<ContextId, HealthCheckSession>> {
        let guarded_session_preparer = self.session_preparer.read().await;
        let mut health_check_sessions = HashMap::new();
        for (context_id, session_preparer) in guarded_session_preparer.iter() {
            health_check_sessions.insert(
                *context_id,
                session_preparer.get_healthcheck_session(context_id).await?,
            );
        }
        Ok(health_check_sessions)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the number of active sessions.
    /// Returns 0 if there are no session preparers.
    pub async fn active_session_count(&self) -> anyhow::Result<u64> {
        let guarded = self.session_preparer.read().await;
        if let Some(session_preparer) = guarded.values().next() {
            session_preparer.active_session_count().await
        } else {
            tracing::warn!("No session_preparer available");
            Ok(0)
        }
    }

    /// Returns the number of inactive sessions.
    /// Returns 0 if there are no session preparers.
    pub async fn inactive_session_count(&self) -> anyhow::Result<u64> {
        let guarded = self.session_preparer.read().await;
        if let Some(session_preparer) = guarded.values().next() {
            session_preparer.inactive_session_count().await
        } else {
            tracing::warn!("No session_preparer available");
            Ok(0)
        }
    }

    /// Inserts a new session preparer into the manager.
    /// This function should be private and only used by the `SessionPreparerManager`.
    async fn insert(&self, context_id: ContextId, session_preparer: SessionPreparer) {
        self.session_preparer
            .write()
            .await
            .insert(context_id, session_preparer);
    }
}

/// This is a shared type between all the modules,
/// it's responsible for creating sessions and holds
/// information on the network setting.
///
/// The session may be empty, when that is the case calling any method will return an error.
pub struct SessionPreparer {
    inner: Option<InnerSessionPreparer>,
}

impl SessionPreparer {
    /// Creates an empty session preparer, which will return an error on any method call.
    pub fn empty() -> Self {
        Self { inner: None }
    }

    /// Creates a new session preparer with the given parameters.
    pub fn new(
        base_kms: BaseKmsStruct,
        threshold: u8,
        my_role: Role,
        role_assignment: RoleAssignment,
        networking_manager: Arc<RwLock<GrpcNetworkingManager>>,
        prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
        prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,
    ) -> Self {
        Self {
            inner: Some(InnerSessionPreparer {
                base_kms,
                threshold,
                my_role,
                role_assignment,
                networking_manager,
                prss_setup_z128,
                prss_setup_z64,
            }),
        }
    }

    pub fn threshold(&self) -> anyhow::Result<u8> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))
            .map(|inner| inner.threshold)
    }

    pub fn my_role(&self) -> anyhow::Result<Role> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))
            .map(|inner| inner.my_role)
    }

    pub fn my_role_string_unchecked(&self) -> String {
        self.inner
            .as_ref()
            .map(|inner| inner.my_role.to_string())
            .unwrap_or("ID UNSPECIFIED".to_string())
    }

    pub async fn own_identity(&self) -> anyhow::Result<Identity> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .own_identity()
            .await
    }

    async fn get_healthcheck_session(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<HealthCheckSession> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .get_healthcheck_session(context_id)
            .await
    }

    pub async fn get_networking(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<threshold_fhe::execution::runtime::session::NetworkingImpl> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .get_networking(session_id, context_id, network_mode)
            .await
    }

    pub async fn get_session_parameters(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SessionParameters> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .get_session_parameters(session_id)
            .await
    }

    pub async fn make_base_session(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .make_base_session(session_id, context_id, network_mode)
            .await
    }

    // Deletes the session with the given session ID from the networking manager.
    pub async fn delete_session(&self, session_id: SessionId) -> anyhow::Result<()> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .networking_manager
            .as_ref()
            .write()
            .await
            .delete_session(session_id);
        Ok(())
    }

    /// Returns the number of active sessions.
    pub async fn active_session_count(&self) -> anyhow::Result<u64> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .networking_manager
            .read()
            .await
            .active_session_count()
            .await)
    }

    /// Returns the number of inactive sessions.
    pub async fn inactive_session_count(&self) -> anyhow::Result<u64> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .networking_manager
            .read()
            .await
            .inactive_session_count()
            .await)
    }

    /// Make a small session with Z128 PRSS for the Async network mode.
    pub async fn make_small_async_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .make_small_session_z128(session_id, context_id, NetworkMode::Async)
            .await
    }

    /// Make a small session with Z64 PRSS for the Async network mode.
    pub async fn make_small_async_session_z64(
        &self,
        session_id: SessionId,
        context_id: ContextId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .make_small_session_z64(session_id, context_id, NetworkMode::Async)
            .await
    }

    /// Make a small session with Z128 PRSS for the Sync network mode.
    pub async fn make_small_sync_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .make_small_session_z128(session_id, context_id, NetworkMode::Sync)
            .await
    }

    /// Make a small session with Z64 PRSS for the Sync network mode.
    pub async fn make_small_sync_session_z64(
        &self,
        session_id: SessionId,
        context_id: ContextId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .make_small_session_z64(session_id, context_id, NetworkMode::Sync)
            .await
    }

    pub async fn new_instance(&self) -> Self {
        match self.inner.as_ref() {
            None => Self { inner: None },
            Some(inner) => Self {
                inner: Some(inner.new_instance().await),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test_session(
        base_kms: BaseKmsStruct,
        prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
        prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,
    ) -> Self {
        Self {
            inner: Some(InnerSessionPreparer::new_test_session(
                base_kms,
                prss_setup_z128,
                prss_setup_z64,
            )),
        }
    }
}

struct InnerSessionPreparer {
    pub base_kms: BaseKmsStruct,
    pub threshold: u8,
    pub my_role: Role,
    pub role_assignment: RoleAssignment,
    pub networking_manager: Arc<RwLock<GrpcNetworkingManager>>,
    pub prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    pub prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,
}

impl InnerSessionPreparer {
    async fn own_identity(&self) -> anyhow::Result<Identity> {
        let id = some_or_tonic_abort(
            self.role_assignment.get(&self.my_role),
            "Could not find my own identity in role assignments".to_string(),
        )?;
        Ok(id.to_owned())
    }

    async fn get_healthcheck_session(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<HealthCheckSession> {
        let context_id = context_id.derive_session_id()?;
        let nm = self.networking_manager.read().await;

        let health_check_session = nm
            .make_healthcheck_session(context_id, &self.role_assignment, self.my_role)
            .await?;
        Ok(health_check_session)
    }

    async fn get_networking(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<threshold_fhe::execution::runtime::session::NetworkingImpl> {
        // We need to convert [ContextId] type to [SessionId]
        // because the core/threshold library is only aware of the [SessionId]
        // since we cannot store something as long as ContextId in the x509 certificate.
        let context_id = context_id.derive_session_id()?;
        let nm = self.networking_manager.read().await;

        let networking = nm
            .make_network_session(
                session_id,
                context_id,
                &self.role_assignment,
                self.my_role,
                network_mode,
            )
            .await?;
        Ok(networking)
    }

    async fn get_session_parameters(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SessionParameters> {
        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            self.my_role,
            self.role_assignment.keys().cloned().collect(),
        )?;
        Ok(parameters)
    }

    async fn make_base_session(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        let networking = self
            .get_networking(session_id, context_id, network_mode)
            .await;

        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            self.my_role,
            self.role_assignment.keys().cloned().collect(),
        )?;
        let base_session =
            BaseSession::new(parameters, networking?, self.base_kms.new_rng().await)?;
        Ok(base_session)
    }

    async fn make_small_session_z128(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        let base_session = self
            .make_base_session(session_id, context_id, network_mode)
            .await?;
        let prss_setup = some_or_tonic_abort(
            self.prss_setup_z128.read().await.clone(),
            "No PRSS setup Z128 exists".to_string(),
        )?;
        let prss_state =
            spawn_compute_bound(move || prss_setup.new_prss_session_state(session_id)).await?;

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
        network_mode: NetworkMode,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        let base_session = self
            .make_base_session(session_id, context_id, network_mode)
            .await?;
        let prss_setup = some_or_tonic_abort(
            self.prss_setup_z64.read().await.clone(),
            "No PRSS setup Z64 exists".to_string(),
        )?;
        let prss_state = prss_setup.new_prss_session_state(session_id);

        let session = SmallSession {
            base_session,
            prss_state,
        };
        Ok(session)
    }

    /// Retuns a copy of the `SessionPreparer` with a fresh randomness generator so it is safe to use.
    async fn new_instance(&self) -> Self {
        Self {
            base_kms: self.base_kms.new_instance().await,
            threshold: self.threshold,
            my_role: self.my_role,
            role_assignment: self.role_assignment.clone(),
            networking_manager: self.networking_manager.clone(),
            prss_setup_z128: self.prss_setup_z128.clone(),
            prss_setup_z64: self.prss_setup_z64.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test_session(
        base_kms: BaseKmsStruct,
        prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
        prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,
    ) -> Self {
        use threshold_fhe::networking::grpc::GrpcNetworkingManager;

        let role_assignment = RoleAssignment {
            inner: HashMap::from_iter((1..=4).map(|i| {
                (
                    Role::indexed_from_one(i),
                    Identity::new("localhost".to_string(), 8080 + i as u16, None),
                )
            })),
        };
        let networking_manager = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(None, None, false).unwrap(),
        ));

        Self {
            base_kms,
            threshold: 1,
            my_role: Role::indexed_from_one(1),
            role_assignment,
            networking_manager,
            prss_setup_z128,
            prss_setup_z64,
        }
    }
}
