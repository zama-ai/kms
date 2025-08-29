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
use crate::{engine::base::BaseKmsStruct, some_or_tonic_abort};

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
}

impl SessionPreparer {
    pub fn own_identity(&self) -> anyhow::Result<Identity> {
        let id = some_or_tonic_abort(
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

    pub fn get_session_parameters(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SessionParameters> {
        let own_identity = self.own_identity()?;
        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            own_identity,
            self.role_assignments.clone(),
        )?;
        Ok(parameters)
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

    pub async fn prepare_ddec_data_from_sessionid_z64(
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
    pub async fn new_instance(&self) -> Self {
        Self {
            base_kms: self.base_kms.new_instance().await,
            threshold: self.threshold,
            my_id: self.my_id,
            role_assignments: self.role_assignments.clone(),
            networking_strategy: self.networking_strategy.clone(),
            prss_setup_z128: self.prss_setup_z128.clone(),
            prss_setup_z64: self.prss_setup_z64.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test_session(with_prss: bool) -> Self {
        use threshold_fhe::networking::{grpc::GrpcNetworkingManager, Networking};

        use crate::cryptography::internal_crypto_types::gen_sig_keys;

        let (_pk, sk) = gen_sig_keys(&mut rand::rngs::OsRng);

        let role_assignments = RoleAssignment::from_iter((1..=4).map(|i| {
            (
                Role::indexed_from_one(i),
                Identity("localhost".to_string(), 8080 + i as u16),
            )
        }));
        let own_identity = role_assignments
            .get(&Role::indexed_from_one(1))
            .cloned()
            .unwrap();

        let networking_manager = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(own_identity.to_owned(), None, None).unwrap(),
        ));

        let networking_strategy: Arc<RwLock<NetworkingStrategy>> = Arc::new(RwLock::new(Box::new(
            move |session_id, roles, network_mode| {
                let nm = networking_manager.clone();
                Box::pin(async move {
                    let manager = nm.read().await;
                    let impl_networking = manager.make_session(session_id, roles, network_mode)?;
                    Ok(impl_networking as Arc<dyn Networking + Send + Sync>)
                })
            },
        )));

        let (prss_setup_z128, prss_setup_z64) = if with_prss {
            (
                Arc::new(RwLock::new(Some(PRSSSetup::new_testing_prss(
                    vec![],
                    vec![],
                )))),
                Arc::new(RwLock::new(Some(PRSSSetup::new_testing_prss(
                    vec![],
                    vec![],
                )))),
            )
        } else {
            (Arc::new(RwLock::new(None)), Arc::new(RwLock::new(None)))
        };

        Self {
            base_kms: BaseKmsStruct::new(sk).unwrap(),
            threshold: 1,
            my_id: 1,
            role_assignments,
            networking_strategy,
            prss_setup_z128,
            prss_setup_z64,
        }
    }
}
