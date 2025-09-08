// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

// === External Crates ===
use kms_grpc::RequestId;
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        runtime::{
            party::{Identity, Role, RoleAssignment},
            session::{BaseSession, SessionParameters, SmallSession},
        },
        small_execution::prss::{DerivePRSSState, PRSSSetup},
    },
    networking::{grpc::GrpcNetworkingManager, NetworkMode},
    session_id::SessionId,
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
    pub(crate) async fn get(&self, request_id: &RequestId) -> anyhow::Result<SessionPreparer> {
        self.inner.get(request_id).await
    }

    /// Inserts a new session preparer into the manager.
    pub(crate) async fn insert(&self, request_id: RequestId, session_preparer: SessionPreparer) {
        self.inner.insert(request_id, session_preparer).await
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
    session_preparer: Arc<RwLock<HashMap<RequestId, SessionPreparer>>>,
    name: String,
}

impl SessionPreparerGetter {
    /// Returns a new instance of the session preparer for the given context ID.
    pub async fn get(&self, request_id: &RequestId) -> anyhow::Result<SessionPreparer> {
        let guarded_session_preparer = self.session_preparer.read().await;
        match guarded_session_preparer.get(request_id) {
            Some(session_preparer) => Ok(session_preparer.new_instance().await),
            None => Err(anyhow::anyhow!(
                "No session preparer found for context ID: {}",
                request_id
            )),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Inserts a new session preparer into the manager.
    /// This function should be private and only used by the `SessionPreparerManager`.
    async fn insert(&self, request_id: RequestId, session_preparer: SessionPreparer) {
        self.session_preparer
            .write()
            .await
            .insert(request_id, session_preparer);
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

    pub async fn get_networking(
        &self,
        session_id: SessionId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<threshold_fhe::execution::runtime::session::NetworkingImpl> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .get_networking(session_id, network_mode)
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
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .make_base_session(session_id, network_mode)
            .await
    }

    pub async fn prepare_ddec_data_from_sessionid_z128(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .prepare_ddec_data_from_sessionid_z128(session_id)
            .await
    }

    pub async fn prepare_ddec_data_from_sessionid_z64(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        self.inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(ERR_SESSION_NOT_INITIALIZED))?
            .prepare_ddec_data_from_sessionid_z64(session_id)
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

    async fn get_networking(
        &self,
        session_id: SessionId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<threshold_fhe::execution::runtime::session::NetworkingImpl> {
        let nm = self.networking_manager.read().await;
        let networking = nm
            .make_session(session_id, &self.role_assignment, network_mode)
            .await?;
        Ok(networking)
    }

    pub async fn get_session_parameters(
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

    pub async fn make_base_session(
        &self,
        session_id: SessionId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        let networking = self.get_networking(session_id, network_mode).await;

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

    pub async fn prepare_ddec_data_from_sessionid_z128(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        //DDec for small session is only online, so requires only Async network
        let base_session = self
            .make_base_session(session_id, NetworkMode::Async)
            .await?;
        let prss_setup = some_or_tonic_abort(
            self.prss_setup_z128.read().await.clone(),
            "No PRSS setup Z128 exists".to_string(),
        )?;
        let prss_state = prss_setup.new_prss_session_state(session_id);

        let session = SmallSession {
            base_session,
            prss_state,
        };
        Ok(session)
    }

    async fn prepare_ddec_data_from_sessionid_z64(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        //DDec for small session is only online, so requires only Async network
        let base_session = self
            .make_base_session(session_id, NetworkMode::Async)
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

        let role_assignment = RoleAssignment::from_iter((1..=4).map(|i| {
            (
                Role::indexed_from_one(i),
                Identity("localhost".to_string(), 8080 + i as u16),
            )
        }));
        let networking_manager = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(
                Role::indexed_from_one(1),
                None,
                None,
                false,
                Arc::new(RwLock::new(role_assignment.clone())),
            )
            .unwrap(),
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
