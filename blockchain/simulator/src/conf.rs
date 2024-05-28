use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct SimConfig {
    pub addresses: Vec<String>,
    pub contract: String,
    pub mnemonic: String,
}

pub struct Settings<'a> {
    pub path: Option<&'a str>,
}

impl<'a> Settings<'a> {
    pub fn init_conf(&self) -> Result<SimConfig, ConfigError> {
        let mut s = Config::builder();

        if let Some(path) = self.path {
            s = s.add_source(File::with_name(path).required(true))
        } else {
            s = s.add_source(File::with_name("config/default").required(true))
        }

        let settings = s.build()?.try_deserialize()?;

        Ok(settings)
    }
}
