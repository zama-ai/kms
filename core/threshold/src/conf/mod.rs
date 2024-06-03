use std::env;
use std::str::FromStr;

use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, Display, EnumString};
use typed_builder::TypedBuilder;

use crate::execution::runtime::party::{Identity, Role};

lazy_static::lazy_static! {
    pub static ref ENVIRONMENT: Mode = mode();
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Party {
    address: String,
    port: u16,
    id: usize,
    choreoport: u16,
}

impl Party {
    /// Returns the address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the id.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns the choreographer port.
    pub fn choreoport(&self) -> u16 {
        self.choreoport
    }
}

impl From<&Party> for Role {
    fn from(party_conf: &Party) -> Self {
        Role::indexed_by_one(party_conf.id)
    }
}

impl From<&Party> for Identity {
    fn from(party_conf: &Party) -> Self {
        Identity::from(&format!("{}:{}", party_conf.address, party_conf.port))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Tracing {
    //service_name did not work well with the config builder env variable
    //as _ was reconginzed as a special character for field of a struct
    service_name: String,
    endpoint: String,
}

impl Tracing {
    /// Returns the service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Returns the endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[derive(Default, Display, Deserialize, Serialize, Clone, EnumString, AsRefStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum Mode {
    #[default]
    Local,
    #[strum(serialize = "dev")]
    Development,
    #[strum(serialize = "choreo")]
    Choreographer,
    Stage,
    #[strum(serialize = "prod")]
    Production,
    #[cfg(test)]
    Test,
}

#[derive(TypedBuilder)]
pub struct Settings<'a> {
    #[builder(default, setter(strip_option))]
    path: Option<&'a str>,
}

fn mode() -> Mode {
    env::var("RUN_MODE")
        .map(|enum_str| Mode::from_str(enum_str.as_str()).unwrap_or_default())
        .unwrap_or_else(|_| Mode::Local)
}

impl<'a> Settings<'a> {
    /// Creates a new instance of `Settings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created or deserialized.
    pub fn init_conf<'de, T: Deserialize<'de>>(&self) -> Result<T, ConfigError> {
        let mut s = Config::builder();

        //Build settings from path
        if let Some(path) = self.path {
            s = s.add_source(File::with_name(path).required(false))
        };

        //Or from environmnent variable
        let s = s
            .add_source(config::Environment::default().prefix("DDEC").separator("-"))
            .build()?;

        let settings: T = s.try_deserialize()?;

        Ok(settings)
    }
}

#[cfg(feature = "choreographer")]
pub mod choreo;

pub mod constants;
pub mod party;
pub mod telemetry;
