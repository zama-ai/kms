use std::sync::Arc;

use kms_lib::{
    conf::{init_conf_kms_core_telemetry, CoreConfig},
    cryptography::{attestation::make_security_module, central_kms::SoftwareKms},
    rpc::run_server,
    threshold::threshold_kms::threshold_server_init,
    vault::{
        aws::build_aws_sdk_config,
        keychain::{awskms::build_aws_kms_client, make_keychain},
        storage::{make_storage, s3::build_s3_client, StorageCache, StorageType},
        Vault,
    },
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
    let core_config: CoreConfig = init_conf_kms_core_telemetry(&args.config_file)?;
    let party_id = core_config.threshold.as_ref().map(|t| t.my_id);

    // common AWS configuration
    let aws_sdk_config = match core_config.aws {
        Some(ref aws_config) => Some(
            build_aws_sdk_config(aws_config.region.clone(), aws_config.imds_endpoint.clone()).await,
        ),
        None => None,
    };

    // AWS S3 client
    let need_s3_client = core_config
        .public_vault
        .as_ref()
        .map(|v| v.storage.scheme() == "s3")
        .unwrap_or(false)
        || core_config
            .private_vault
            .as_ref()
            .map(|v| v.storage.scheme() == "s3")
            .unwrap_or(false);
    let s3_client = if need_s3_client {
        Some(
            build_s3_client(
                aws_sdk_config
                    .as_ref()
                    .expect("AWS configuration must be provided"),
                core_config
                    .aws
                    .as_ref()
                    .and_then(|aws| aws.s3_endpoint.clone()),
            )
            .await?,
        )
    } else {
        None
    };

    // AWS KMS client
    let need_awskms_client = core_config
        .public_vault
        .as_ref()
        .and_then(|v| v.keychain.as_ref().map(|k| k.scheme() == "awskms"))
        .unwrap_or(false)
        || core_config
            .private_vault
            .as_ref()
            .and_then(|v| v.keychain.as_ref().map(|k| k.scheme() == "awskms"))
            .unwrap_or(false);
    let awskms_client = if need_awskms_client {
        Some(
            build_aws_kms_client(
                aws_sdk_config
                    .as_ref()
                    .expect("AWS configuration must be provided"),
                core_config.aws.and_then(|aws| aws.awskms_endpoint),
            )
            .await,
        )
    } else {
        None
    };

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

    // security module (used for remote attestation with AWS KMS only so far)
    let security_module = if need_awskms_client {
        Some(make_security_module()?)
    } else {
        None
    };

    // public vault
    let public_vault = Vault {
        storage: make_storage(
            core_config.public_vault.map(|v| v.storage),
            StorageType::PUB,
            party_id,
            public_storage_cache,
            s3_client.clone(),
        )?,
        keychain: None,
    };
    // private vault
    let private_keychain = core_config
        .private_vault
        .as_ref()
        .and_then(|v| {
            v.keychain
                .clone()
                .map(|k| make_keychain(k, awskms_client.clone(), security_module.clone()))
        })
        .transpose()?;
    let private_vault = Vault {
        storage: make_storage(
            core_config
                .private_vault
                .as_ref()
                .map(|v| v.storage.clone()),
            StorageType::PRIV,
            party_id,
            private_storage_cache,
            s3_client.clone(),
        )?,
        keychain: private_keychain,
    };
    // backup vault (unlike for private/public storage, there cannot be a
    // default location for backup storage, so there has to be
    // Some(storage_url))
    let backup_vault = core_config
        .backup_vault
        .as_ref()
        .map(|v| {
            make_storage(
                Some(v.storage.clone()),
                StorageType::BACKUP,
                party_id,
                None,
                s3_client,
            )
            .and_then(|storage| {
                v.keychain
                    .clone()
                    .map(|k| make_keychain(k, awskms_client, security_module))
                    .transpose()
                    .map(|keychain| Vault { storage, keychain })
            })
        })
        .transpose()?;

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let thread_health_reporter = Arc::new(RwLock::new(health_reporter));
    // initialize KMS core
    match core_config.threshold {
        Some(threshold_config) => {
            let kms = threshold_server_init(
                threshold_config,
                public_vault,
                private_vault,
                backup_vault,
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
                public_vault,
                private_vault,
                backup_vault,
                core_config.rate_limiter_conf,
            )
            .await?;
            run_server(
                core_config.service,
                kms,
                thread_health_reporter,
                health_service,
                std::future::pending(),
            )
            .await?
        }
    }
    Ok(())
}
