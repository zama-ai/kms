use conf_trace::conf::{Settings, Tracing};
use conf_trace::telemetry::init_tracing;
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default, Debug)]
pub struct ContractFee {
    pub amount: u64,
    pub denom: String,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default)]
pub struct SignKeyConfig {
    pub mnemonic: Option<String>,
    pub bip32: Option<String>,
}

impl std::fmt::Debug for SignKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignKeyConfig")
            .field("mnemonic", &"<REDACTED>")
            .field("bip32", &"<REDACTED>")
            .finish()
    }
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default, Debug)]
pub struct BlockchainConfig {
    pub addresses: Vec<String>,
    pub contract: String,
    pub fee: ContractFee,
    pub signkey: SignKeyConfig,
    pub kv_store_address: Option<String>,
}

/// Three timeouts that controls the polling logic
/// to fetch results from the core.
/// All times are in seconds.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct TimeoutTriple {
    /// The time to wait before starting to poll.
    pub initial_wait_time: u64,
    /// The time to wait between polling.
    pub retry_interval: u64,
    /// How many times to poll before giving up.
    pub max_poll_count: u64,
}

impl TimeoutTriple {
    pub fn new(initial_wait_time: u64, retry_interval: u64, max_poll_count: u64) -> Self {
        Self {
            initial_wait_time,
            retry_interval,
            max_poll_count,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TimeoutConfig {
    pub channel_timeout: u64,
    pub crs: TimeoutTriple,
    pub keygen: TimeoutTriple,
    pub insecure_keygen: TimeoutTriple,
    pub preproc: TimeoutTriple,
    pub decryption: TimeoutTriple,
    pub reencryption: TimeoutTriple,
    pub zkp: TimeoutTriple,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            channel_timeout: 60,
            // CRS: 2 hours total, check each minute
            crs: TimeoutTriple::new(60, 60, 120),
            // Key-Gen: 20 hours, wait 5 hours first, then poll for the next 15 hours
            keygen: TimeoutTriple::new(18000, 15000, 150),
            // Insecure Key-Gen: 2 minutes
            insecure_keygen: TimeoutTriple::new(10, 5, 24),
            // Pre-Processing: 20 hours, wait 5 hours first, then poll for the next 15 hours
            preproc: TimeoutTriple::new(18000, 15000, 150),
            // Decryption: 2 minutes 10s total
            decryption: TimeoutTriple::new(10, 5, 24),
            // Re-Encryption: 2 minutes 10s total
            reencryption: TimeoutTriple::new(10, 5, 24),
            // ZKP: 2 minutes 10s total
            zkp: TimeoutTriple::new(10, 5, 24),
        }
    }
}

impl TimeoutConfig {
    /// These are the testing defaults, used for testing parameters.
    pub fn testing_default() -> Self {
        Self {
            channel_timeout: 60,
            crs: TimeoutTriple::new(1, 5, 50),
            keygen: TimeoutTriple::new(1, 5, 50),
            insecure_keygen: TimeoutTriple::new(1, 5, 50),
            preproc: TimeoutTriple::new(1, 5, 50),
            decryption: TimeoutTriple::new(1, 5, 50),
            reencryption: TimeoutTriple::new(1, 5, 50),
            zkp: TimeoutTriple::new(1, 5, 50),
        }
    }

    /// These are the mocking/dummy defaults, used when the core is a dummy.
    pub fn mocking_default() -> Self {
        Self {
            channel_timeout: 60,
            crs: TimeoutTriple::new(1, 1, 10),
            keygen: TimeoutTriple::new(1, 1, 10),
            insecure_keygen: TimeoutTriple::new(1, 1, 10),
            preproc: TimeoutTriple::new(1, 1, 10),
            decryption: TimeoutTriple::new(1, 1, 10),
            reencryption: TimeoutTriple::new(1, 1, 10),
            zkp: TimeoutTriple::new(1, 1, 10),
        }
    }
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default, Debug)]
pub struct OracleConfig {
    pub addresses: Vec<String>,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default, Debug)]
pub struct StoreConfig {
    pub url: String,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default, Debug)]
pub struct ConnectorConfig {
    pub tick_interval_secs: u64,
    pub storage_path: String,
    pub tracing: Option<Tracing>,
    pub blockchain: BlockchainConfig,
    pub core: CoreConfig,
    pub oracle: OracleConfig,
    pub store: StoreConfig,
}

impl BlockchainConfig {
    pub fn grpc_addresses(&self) -> Vec<&str> {
        self.addresses.iter().map(|s| s.as_str()).collect()
    }
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default, Debug)]
pub struct CoreConfig {
    pub addresses: Vec<String>,
    pub timeout_config: TimeoutConfig,
}

impl CoreConfig {
    pub fn addresses(&self) -> Vec<&str> {
        self.addresses.iter().map(|s| s.as_str()).collect()
    }
}

pub fn init_conf(config_file: &str) -> anyhow::Result<ConnectorConfig> {
    Settings::builder()
        .path(config_file)
        .env_prefix("ASC_CONN")
        .parse_keys(vec!["blockchain.addresses", "core.addresses"])
        .build()
        .init_conf()
        .map_err(|e| e.into())
}

pub fn init_conf_with_trace(config_file: &str) -> anyhow::Result<ConnectorConfig> {
    let conf = init_conf(config_file)?;
    let tracing = conf
        .tracing
        .clone()
        .unwrap_or_else(|| Tracing::builder().service_name("asc_connector").build());
    init_tracing(tracing)?;
    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_config() {
        let envs: [(&str, Option<&str>); 2] = [
            ("ASC_CONN___CORE__ADDRESSES", None),
            ("ASC_CONN___BLOCKCHAIN__ADDRESSES", None),
        ];

        temp_env::with_vars(envs, || {
            let conf: ConnectorConfig = init_conf("config/default").unwrap();

            assert_eq!(conf.tick_interval_secs, 1);
            assert_eq!(conf.storage_path, "./temp/events.toml");

            // coordinator configs
            assert_eq!(conf.core.addresses, vec!["http://localhost:50051"]);
            assert_eq!(conf.core.timeout_config.channel_timeout, 60);
            assert_eq!(
                conf.core.timeout_config.decryption,
                TimeoutTriple {
                    initial_wait_time: 1,
                    retry_interval: 1,
                    max_poll_count: 24,
                }
            );

            // blockchain configs
            assert_eq!(conf.blockchain.addresses, vec!["http://localhost:9090"]);
            assert_eq!(conf.blockchain.fee.amount, 3_000_000);
            assert_eq!(conf.blockchain.fee.denom, "ucosm");

            // store configs
            assert_eq!(conf.store.url, "http://localhost:8088");
        });
    }

    #[test]
    fn core_config_with_rewrite_env() {
        let envs = [
            (
                "ASC_CONN__CORE__ADDRESSES",
                Some("http://localhost:50051,http://localhost:50052"),
            ),
            (
                "ASC_CONN__BLOCKCHAIN__ADDRESSES",
                Some("http://localhost:9091"),
            ),
        ];
        temp_env::with_vars(envs, || {
            let conf: ConnectorConfig = init_conf("config/default").unwrap();

            // coordinator configs
            assert_eq!(
                conf.core.addresses,
                vec!["http://localhost:50051", "http://localhost:50052"]
            );
            // blockchain configs
            assert_eq!(conf.blockchain.addresses, vec!["http://localhost:9091"]);
        });
    }
}
