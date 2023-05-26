use crate::circuit::Circuit;
use crate::computation::SessionId;
use crate::execution::distributed::NetworkingImpl;
use crate::execution::player::{Identity, Role, RoleAssignment};
use serde::Deserialize;
use std::path::Path;
use std::str::FromStr;

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
    pub threshold: u8,
}

#[derive(Debug, Deserialize)]
pub struct RoleConfig {
    pub id: u64,
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
) -> Result<(RoleAssignment, Circuit, u8), Box<dyn std::error::Error>> {
    let session_config = SessionConfig::from_str(&std::fs::read_to_string(session_config_file)?)?;

    let role_assignment: RoleAssignment = session_config
        .roles
        .iter()
        .map(|role_config| {
            let role = Role::from(role_config.id);
            let identity = Identity::from(&role_config.identity);
            (role, identity)
        })
        .collect();

    let threshold = session_config.security.threshold;

    let comp_bytes = std::fs::read(&session_config.computation.path)?;
    let circuit = Circuit::try_from(&comp_bytes[..]).unwrap();

    Ok((role_assignment, circuit, threshold))
}
