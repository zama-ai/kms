// === Standard Library ===
use std::sync::Arc;

// === External Crates ===
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        runtime::{
            party::{Identity, Role, RoleAssignment},
            session::{BaseSession, SessionParameters, SmallSession},
        },
        small_execution::prss::{DerivePRSSState, PRSSSetup},
    },
    networking::{NetworkMode, NetworkingStrategy},
    session_id::SessionId,
};
use tokio::sync::RwLock;

// === Internal Crate ===
use crate::{engine::base::BaseKmsStruct, tonic_some_or_err};

/// This is a shared type between all the modules,
/// it's responsible for creating sessions and holds
/// information on the network setting.
pub struct SessionPreparer {
    pub base_kms: BaseKmsStruct,
    pub threshold: u8,
    pub my_id: usize,
    pub role_assignments: RoleAssignment,
    pub networking_strategy: Arc<RwLock<NetworkingStrategy>>,
    pub prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>, // TODO make generic?
    pub prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,   // TODO make generic?
    // This is a workaround to delete sessions, later we'll remove networking_strategy.
    pub(crate) networking_manager:
        Arc<RwLock<threshold_fhe::networking::grpc::GrpcNetworkingManager>>,
}

impl SessionPreparer {
    pub fn own_identity(&self) -> anyhow::Result<Identity> {
        let id = tonic_some_or_err(
            self.role_assignments
                .get(&Role::indexed_from_one(self.my_id)),
            "Could not find my own identity in role assignments".to_string(),
        )?;
        Ok(id.to_owned())
    }

    pub async fn get_networking(
        &self,
        session_id: SessionId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<threshold_fhe::execution::runtime::session::NetworkingImpl> {
        let strat = self.networking_strategy.read().await;
        let networking = (strat)(session_id, self.role_assignments.clone(), network_mode).await?;
        Ok(networking)
    }

    pub async fn make_base_session(
        &self,
        session_id: SessionId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSession> {
        let networking = self.get_networking(session_id, network_mode).await;
        let own_identity = self.own_identity()?;

        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            own_identity,
            self.role_assignments.clone(),
        )?;
        let base_session =
            BaseSession::new(parameters, networking?, self.base_kms.new_rng().await)?;
        Ok(base_session)
    }

    // TODO we should return something here with a drop implementation that
    // destroys the session when dropped.
    pub async fn prepare_ddec_data_from_sessionid_z128(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        //DDec for small session is only online, so requires only Async network
        let base_session = self
            .make_base_session(session_id, NetworkMode::Async)
            .await?;
        let prss_setup = tonic_some_or_err(
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

    pub async fn prepare_ddec_data_from_sessionid_z64(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        //DDec for small session is only online, so requires only Async network
        let base_session = self
            .make_base_session(session_id, NetworkMode::Async)
            .await?;
        let prss_setup = tonic_some_or_err(
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
    pub async fn new_instance(&self) -> Self {
        Self {
            base_kms: self.base_kms.new_instance().await,
            threshold: self.threshold,
            my_id: self.my_id,
            role_assignments: self.role_assignments.clone(),
            networking_strategy: self.networking_strategy.clone(),
            prss_setup_z128: self.prss_setup_z128.clone(),
            prss_setup_z64: self.prss_setup_z64.clone(),
            networking_manager: self.networking_manager.clone(),
        }
    }

    pub async fn destroy_session(&self, session_id: SessionId) {
        // consider using something like `tokio_util::time::delay_queue::DelayQueue` for session management
        // https://docs.rs/tokio-util/latest/tokio_util/time/delay_queue/struct.DelayQueue.html
        // so inserting completed sessions to a queue and then have a task that periodically checks the queue
        // and deletes sessions that are ready to be deleted.

        let networking_manager = self.networking_manager.clone();
        tokio::spawn(async move {
            // wait for 60 seconds before deleting
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let nm = networking_manager.read().await;
            nm.delete_session(session_id)
        });
    }
}
