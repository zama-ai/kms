use std::sync::Arc;

use kms_lib::{
    conf::{init_conf_trace, CoreConfig},
    cryptography::central_kms::SoftwareKms,
    kms::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc::run_server,
    storage::{make_storage, StorageCache, StorageProxy, StorageType},
    threshold::threshold_kms::threshold_server_init,
};

use clap::Parser;
use tokio::sync::RwLock;

pub const SIG_SK_BLOB_KEY: &str = "private_sig_key";
pub const SIG_PK_BLOB_KEY: &str = "public_sig_key";

#[derive(Parser)]
#[clap(name = "KMS server")]
#[clap(
    about = "We support two execution modes, `centralized` or `threshold`, that have to be specified with the `mode` parameter in the configuration file. \
    See the help page for additional details (`kms-server --help`). \n
    Use the following to run a threshold KMS node with the default configuration: \n
    ./kms-server --config-file core/service/config/default_1.toml \n
    or using cargo : \n
    cargo run --bin kms-server -- --config-file core/service/config/default_1.toml \n
    Use the following to run a centralized KMS node with the default configuration: \n
    ./kms-server --config-file core/service/config/default_centralized.toml \n
    or using cargo : \n
    cargo run --bin kms-server -- --config-file core/service/config/default_centralized.toml \n

    If no configuration file is specified, the default configuration will be used \
    (core/service/config/default_1.toml). \n
    Note that key material and TLS certificates MUST exist when starting the server and be stored in the path specified by the configuration file. \n
    Please consult the `kms-gen-keys` and `kms-gen-tls-certs` binaries for details on generating key material and certificates."
)]
struct KmsArgs {
    #[clap(
        long,
        default_value = "config/default_1.toml",
        help = "path to the configuration file"
    )]
    config_file: String,
}

/// Starts a KMS server.
/// We support two execution modes, `centralized` or `threshold`, that have to be specified with the `mode` parameter in the configuration file.
/// See the help page for additional details.
/// Note that key material MUST exist when starting the server and be stored in the path specified by the configuration file.
/// Please consult the `kms-gen-keys` binary for details on generating key material.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = KmsArgs::parse();
    let core_config: CoreConfig = init_conf_trace(&args.config_file).await?;
    let party_id = core_config.threshold.as_ref().map(|t| t.my_id);

    // storage cache (don't forget to remove `storage_cache_size` from the
    // config if weird inconsistencies appear)
    let public_storage_cache = core_config
        .public_vault
        .as_ref()
        .and_then(|v| v.storage_cache_size.and_then(|s| StorageCache::new(s).ok()));
    let private_storage_cache = core_config
        .private_vault
        .as_ref()
        .and_then(|v| v.storage_cache_size.and_then(|s| StorageCache::new(s).ok()));

    // initialize storage
    let public_storage = make_storage(
        core_config.aws.clone(),
        core_config.public_vault.map(|v| v.storage),
        None,
        StorageType::PUB,
        party_id,
        public_storage_cache,
    )
    .await?;
    let private_storage = make_storage(
        core_config.aws,
        core_config.private_vault.clone().map(|v| v.storage),
        core_config.private_vault.and_then(|v| v.keychain),
        StorageType::PRIV,
        party_id,
        private_storage_cache,
    )
    .await?;

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let thread_health_reporter = Arc::new(RwLock::new(health_reporter));
    // initialize KMS core
    match core_config.threshold {
        Some(threshold_config) => {
            let kms = threshold_server_init(
                threshold_config,
                public_storage,
                private_storage,
                false,
                core_config.rate_limiter_conf,
                thread_health_reporter.clone(),
                std::future::pending(),
            )
            .await?;
            run_server(
                core_config.service,
                kms,
                thread_health_reporter,
                health_service,
                std::future::pending(),
            )
            .await?;
        }
        None => {
            let kms = SoftwareKms::new(
                public_storage,
                private_storage,
                core_config.rate_limiter_conf,
            )
            .await?;
            run_server(
                core_config.service,
                kms,
                thread_health_reporter.clone(),
                health_service,
                std::future::pending(),
            )
            .await?;
            thread_health_reporter
                .write()
                .await
                .set_serving::<CoreServiceEndpointServer<SoftwareKms<StorageProxy, StorageProxy>>>()
                .await;
        }
    }
    Ok(())
}
