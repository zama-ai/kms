// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

use aes_prng::AesRng;
// === External Crates ===
use kms_grpc::identifiers::{ContextId, EpochId};
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        runtime::{
            party::{Identity, MpcIdentity, Role, RoleAssignment},
            sessions::{
                base_session::BaseSession, session_parameters::SessionParameters,
                small_session::SmallSession,
            },
        },
        small_execution::prss::{DerivePRSSState, PRSSSetup},
    },
    networking::{
        grpc::GrpcNetworkingManager, health_check::HealthCheckSession, tls::AttestedVerifier,
        NetworkMode,
    },
    session_id::SessionId,
};
use tokio::sync::{Mutex, RwLock};

use crate::engine::context::ContextInfo;

struct Context {
    my_role: Role,
    // A Context always hold only a RoleAssignment on Role
    // to build a RoleAssignment on a TwoSetRole,
    // we need 2 contexts
    role_assignment: RoleAssignment<Role>,
    threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PRSSSetupCombinedVersioned {
    V0(PRSSSetupCombined),
}

/// Public because it's used by storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(PRSSSetupCombinedVersioned)]
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

#[derive(Clone)]
pub(crate) struct SessionMaker {
    networking_manager: Arc<RwLock<GrpcNetworkingManager>>,
    context_map: Arc<RwLock<ContextMap>>,
    epoch_map: Arc<RwLock<HashMap<EpochId, PRSSSetupCombined>>>,
    verifier: Option<Arc<AttestedVerifier>>, // optional as it's not used when there's no TLS
    rng: Arc<Mutex<AesRng>>,
}

impl SessionMaker {
    pub(crate) fn new(
        networking_manager: Arc<RwLock<GrpcNetworkingManager>>,
        verifier: Option<Arc<AttestedVerifier>>,
        rng: AesRng,
    ) -> Self {
        Self {
            networking_manager,
            context_map: Arc::new(RwLock::new(HashMap::new())),
            epoch_map: Arc::new(RwLock::new(HashMap::new())),
            verifier,
            rng: Arc::new(Mutex::new(rng)),
        }
    }

    #[cfg(test)]
    pub(crate) async fn context_count(&self) -> usize {
        self.context_map.read().await.len()
    }

    #[cfg(test)]
    pub(crate) async fn epoch_count(&self) -> usize {
        self.epoch_map.read().await.len()
    }

    #[cfg(test)]
    pub(crate) fn empty_dummy_session(rng: AesRng) -> Self {
        let networking_manager = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(None, None, false).unwrap(),
        ));
        Self {
            networking_manager,
            context_map: Arc::new(RwLock::new(HashMap::new())),
            epoch_map: Arc::new(RwLock::new(HashMap::new())),
            verifier: None,
            rng: Arc::new(Mutex::new(rng)),
        }
    }

    #[cfg(test)]
    pub(crate) fn four_party_dummy_session(
        prss_setup_z128: Option<PRSSSetup<ResiduePolyF4Z128>>,
        prss_setup_z64: Option<PRSSSetup<ResiduePolyF4Z64>>,
        rng: AesRng,
    ) -> Self {
        use crate::consts::{DEFAULT_MPC_CONTEXT, PRSS_INIT_REQ_ID};

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

        let default_context_id = *DEFAULT_MPC_CONTEXT;
        let default_context = Context {
            threshold: 1,
            my_role: Role::indexed_from_one(1),
            role_assignment,
        };

        let default_epoch_id = EpochId::try_from(PRSS_INIT_REQ_ID).unwrap();
        let default_prss = match (prss_setup_z128, prss_setup_z64) {
            (Some(z128), Some(z64)) => Some(PRSSSetupCombined {
                prss_setup_z128: z128,
                prss_setup_z64: z64,
                num_parties: 4,
                threshold: 1,
            }),
            _ => None,
        };

        Self {
            networking_manager,
            context_map: Arc::new(RwLock::new(HashMap::from_iter([(
                default_context_id,
                default_context,
            )]))),
            epoch_map: Arc::new(RwLock::new(match default_prss {
                Some(prss) => HashMap::from_iter([(default_epoch_id, prss)]),
                None => HashMap::new(),
            })),
            verifier: None,
            rng: Arc::new(Mutex::new(rng)),
        }
    }

    // Returns the an health check session per context.
    async fn get_healthcheck_session_all_contexts(
        &self,
    ) -> anyhow::Result<HashMap<ContextId, HealthCheckSession<Role>>> {
        let mut health_check_sessions = HashMap::new();
        for (context_id, _) in self.context_map.read().await.iter() {
            health_check_sessions
                .insert(*context_id, self.get_healthcheck_session(context_id).await?);
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

        let health_check_session = nm
            .make_healthcheck_session(&role_assignment, my_role)
            .await?;
        Ok(health_check_session)
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

    async fn add_context(
        &self,
        context_id: ContextId,
        my_role: Role,
        role_assignment: RoleAssignment<Role>,
        threshold: u8,
    ) {
        let mut context_map = self.context_map.write().await;
        context_map.insert(
            context_id,
            Context {
                my_role,
                role_assignment,
                threshold,
            },
        );
    }

    /// Adds information given by [ContextInfo] struct into the session maker.
    pub(crate) async fn add_context_info(
        &self,
        my_role: Role,
        info: &ContextInfo,
    ) -> anyhow::Result<()> {
        let mut role_assignment_map = HashMap::new();
        let mut ca_certs_map = HashMap::new();

        for node in &info.kms_nodes {
            let mpc_url = url::Url::parse(&node.external_url)
                .map_err(|e| anyhow::anyhow!("url parsing error for party: {}", e))?;
            let hostname = mpc_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host"))?;
            let port = mpc_url
                .port()
                .ok_or_else(|| anyhow::anyhow!("missing port"))?;
            role_assignment_map.insert(
                Role::indexed_from_one(node.party_id as usize),
                Identity::new(hostname.to_string(), port, Some(node.mpc_identity.clone())),
            );

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

        self.add_context(
            *info.context_id(),
            my_role,
            role_assignment,
            info.threshold as u8,
        )
        .await;

        match self.verifier.as_ref() {
            Some(verifier) => {
                let context_id_as_session_id = info.context_id().derive_session_id()?;
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
                    .add_context(context_id_as_session_id, ca_certs_map, release_pcrs)
                    .map_err(|e| anyhow::anyhow!("Failed to add context to verifier: {}", e))?;
            }
            _ => { /* do nothing */ }
        }

        Ok(())
    }

    pub(crate) async fn remove_context(&self, context_id: &ContextId) {
        let mut context_map = self.context_map.write().await;
        context_map.remove(context_id);
    }

    pub(crate) async fn add_epoch(&self, epoch_id: EpochId, prss: PRSSSetupCombined) {
        let mut epoch_map = self.epoch_map.write().await;
        epoch_map.insert(epoch_id, prss);
    }

    pub(crate) async fn epoch_exists(&self, epoch_id: &EpochId) -> bool {
        let epoch_map = self.epoch_map.read().await;
        epoch_map.contains_key(epoch_id)
    }

    pub(crate) async fn context_exists(&self, context_id: &ContextId) -> bool {
        let context_map = self.context_map.read().await;
        context_map.contains_key(context_id)
    }

    async fn new_rng(&self) -> AesRng {
        let mut seed = [0u8; crate::consts::RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng = self.rng.lock().await;
            base_rng.fill_bytes(seed.as_mut());
        }
        AesRng::from_seed(seed)
    }

    pub(crate) async fn make_base_session(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        tracing::info!(
            "Making base session: session_id={}, context_id={:?}, network_mode={:?}",
            session_id,
            context_id,
            network_mode
        );
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
            context_info.my_role,
            context_info.role_assignment.keys().cloned().collect(),
        )?;

        let base_session = BaseSession::new(parameters, networking?, self.new_rng().await)?;
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
            let prss_setup = &prss_setup_extended.prss_setup_z128;
            prss_setup.new_prss_session_state(session_id)
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
            let prss_setup = &prss_setup_extended.prss_setup_z64;

            prss_setup.new_prss_session_state(session_id)
        };

        let session = SmallSession {
            base_session,
            prss_state,
        };
        Ok(session)
    }

    async fn get_networking(
        &self,
        session_id: SessionId,
        context_id: ContextId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<
        threshold_fhe::execution::runtime::sessions::base_session::SingleSetNetworkingImpl,
    > {
        let nm = self.networking_manager.read().await;

        let (role_assignment, my_role) = {
            let context_map_guard = self.context_map.read().await;
            let context_info = context_map_guard.get(&context_id).ok_or_else(|| {
                anyhow::anyhow!("Context {} not found in context map", context_id)
            })?;
            (context_info.role_assignment.clone(), context_info.my_role)
        };

        let networking = nm
            .make_network_session(session_id, &role_assignment, my_role, network_mode)
            .await?;
        tracing::debug!(
            "Created networking for session_id={}, context_id={:?}, network_mode={:?}",
            session_id,
            context_id,
            network_mode
        );
        Ok(networking)
    }

    pub(crate) async fn my_identity(&self, context_id: &ContextId) -> anyhow::Result<Identity> {
        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;
        let id = context_info
            .role_assignment
            .get(&context_info.my_role)
            .ok_or_else(|| anyhow::anyhow!("Could not find my own identity in role assignments"))?;
        Ok(id.to_owned())
    }

    pub(crate) async fn my_role(&self, context_id: &ContextId) -> anyhow::Result<Role> {
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

    pub(crate) async fn num_parties(&self, context_id: &ContextId) -> anyhow::Result<usize> {
        let context_map_guard = self.context_map.read().await;
        let context_info = context_map_guard
            .get(context_id)
            .ok_or_else(|| anyhow::anyhow!("Context {} not found in context map", context_id))?;
        Ok(context_info.role_assignment.len())
    }
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

    pub(crate) async fn my_identity(&self, context_id: &ContextId) -> anyhow::Result<Identity> {
        self.inner.my_identity(context_id).await
    }

    pub(crate) async fn my_role(&self, context_id: &ContextId) -> anyhow::Result<Role> {
        self.inner.my_role(context_id).await
    }

    pub(crate) async fn threshold(&self, context_id: &ContextId) -> anyhow::Result<u8> {
        self.inner.threshold(context_id).await
    }

    // Returns the an health check session per context.
    pub(crate) async fn get_healthcheck_session_all_contexts(
        &self,
    ) -> anyhow::Result<HashMap<ContextId, HealthCheckSession<Role>>> {
        self.inner.get_healthcheck_session_all_contexts().await
    }
}
