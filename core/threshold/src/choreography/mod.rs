use crate::execution::runtime::party::{Identity, Role, RoleAssignment};
use crate::execution::runtime::session::NetworkingImpl;
use crate::session_id::SessionId;
use serde::Deserialize;
use std::path::Path;
use std::str::FromStr;

pub mod choreographer;
pub mod grpc;

pub type NetworkingStrategy =
    Box<dyn Fn(SessionId, RoleAssignment) -> NetworkingImpl + Send + Sync>;

#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    pub roles: Vec<RoleConfig>,
    pub computation: ComputationConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize)]
pub struct ComputationConfig {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    pub threshold: u32,
}

#[derive(Debug, Deserialize)]
pub struct RoleConfig {
    pub id: usize,
    pub identity: String,
}

impl FromStr for SessionConfig {
    type Err = toml::de::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s)
    }
}

pub fn parse_session_config_file_with_computation(
    session_config_file: &Path,
) -> Result<(RoleAssignment, u32), Box<dyn std::error::Error>> {
    let session_config = SessionConfig::from_str(&std::fs::read_to_string(session_config_file)?)?;

    let role_assignment: RoleAssignment = session_config
        .roles
        .iter()
        .map(|role_config| {
            let role = Role::indexed_by_one(role_config.id);
            let identity = Identity::from(&role_config.identity);
            (role, identity)
        })
        .collect();

    let threshold = session_config.security.threshold;

    Ok((role_assignment, threshold))
}
