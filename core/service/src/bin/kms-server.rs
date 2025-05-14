use clap::Parser;
use kms_lib::{
    conf::{
        init_conf_kms_core_telemetry,
        threshold::{EnclaveConf, TlsCert, TlsKey},
        CoreConfig,
    },
    cryptography::attestation::{make_security_module, SecurityModule},
    engine::{
        centralized::central_kms::RealCentralizedKms, run_server,
        threshold::service::threshold_server_init,
    },
    vault::{
        aws::build_aws_sdk_config,
        keychain::{awskms::build_aws_kms_client, make_keychain},
        storage::{make_storage, s3::build_s3_client, StorageCache, StorageType},
        Vault,
    },
};
use std::{net::ToSocketAddrs, sync::Arc};
use tokio::net::TcpListener;

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
    let (core_config, tracer_provider, meter_provider) =
        init_conf_kms_core_telemetry::<CoreConfig>(&args.config_file)?;

    tracing::info!("Starting KMS Server with core config: {:?}", &core_config);

    let party_id = core_config.threshold.as_ref().map(|t| t.my_id);

    // common AWS configuration
    let aws_sdk_config = match core_config.aws {
        Some(ref aws_config) => Some(
            build_aws_sdk_config(
                aws_config.region.clone(),
                aws_config.imds_endpoint.clone(),
                aws_config.sts_endpoint.clone(),
            )
            .await,
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
        .private_vault
        .as_ref()
        .and_then(|v| v.keychain.as_ref().map(|k| k.scheme() == "awskms"))
        .unwrap_or(false)
        || core_config
            .backup_vault
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
    let private_keychain_url = core_config
        .private_vault
        .as_ref()
        .and_then(|v| v.keychain.clone());
    let private_keychain = match private_keychain_url {
        Some(k) => Some(make_keychain(k, awskms_client.clone(), security_module.clone()).await?),
        None => None,
    };
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
    let backup_keychain_url = core_config
        .backup_vault
        .as_ref()
        .and_then(|v| v.keychain.clone());
    let backup_keychain = match backup_keychain_url {
        Some(k) => Some(make_keychain(k, awskms_client, security_module.clone()).await?),
        None => None,
    };
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
            .map(|storage| Vault {
                storage,
                keychain: backup_keychain,
            })
        })
        .transpose()?;

    // initialize KMS core
    let service_socket_addr_str = format!(
        "{}:{}",
        core_config.service.listen_address, core_config.service.listen_port
    );
    let service_socket_addr = service_socket_addr_str
        .to_socket_addrs()
        .unwrap_or_else(|e| {
            panic!(
                "Wrong service IP Address: {} \n {:?}",
                core_config.service.listen_address, e
            )
        })
        .next()
        .unwrap_or_else(|| {
            panic!(
                "Failed to parse service IP Address: {}",
                core_config.service.listen_address
            )
        });

    println!("KMS Server service socket address: {}", service_socket_addr);

    let service_listener = TcpListener::bind(service_socket_addr)
        .await
        .unwrap_or_else(|e| panic!("Could not bind to {} \n {:?}", service_socket_addr, e));

    match core_config.threshold {
        Some(threshold_config) => {
            let mpc_socket_addr_str = format!(
                "{}:{}",
                threshold_config.listen_address, threshold_config.listen_port
            );

            let mpc_socket_addr = mpc_socket_addr_str
                .to_socket_addrs()
                .unwrap_or_else(|e| {
                    panic!(
                        "Wrong MPC IP Address: {} \n {:?}",
                        threshold_config.listen_address, e
                    )
                })
                .next()
                .unwrap_or_else(|| {
                    panic!(
                        "Failed to parse MPC IP Address: {}",
                        threshold_config.listen_address
                    )
                });

            let mpc_listener = TcpListener::bind(mpc_socket_addr)
                .await
                .unwrap_or_else(|e| panic!("Could not bind to {} \n {:?}", mpc_socket_addr, e));

            // Communication between MPC parties can be optionally protected
            // with mTLS which requires a TLS certificate valid both for server
            // and client authentication.
            let tls_identity = match threshold_config.tls {
                Some(ref tls) => {
                    let cert_bytes = match tls.cert {
                        TlsCert::Path(ref cert_path) => std::fs::read_to_string(cert_path)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "Failed to open file {}: {}",
                                    cert_path.display(),
                                    e
                                )
                            })?,
                        TlsCert::Pem(ref cert_bytes) => cert_bytes.to_string(),
                    };
                    let cert_pem = x509_parser::pem::parse_x509_pem(cert_bytes.as_ref())?.1;
                    let cert = cert_pem.parse_x509()?;
                    // sanity check: peerlist needs to have an entry for the
                    // current party
                    let my_hostname = &threshold_config
                        .peers
                        .iter()
                        .find(|peer| peer.party_id == threshold_config.my_id)
                        .expect("Peer list does not have an entry for my id")
                        .address;
                    let subject = threshold_fhe::networking::tls::extract_subject_from_cert(&cert)
                        .map_err(|e| anyhow::anyhow!(e))?;
                    if subject != *my_hostname {
                        panic!(
                            "Certificate subject {subject} does not match hostname {my_hostname}"
                        );
                    }
                    // Our variety of mTLS can optionally use remote attestation
                    // of the software build run by MPC parties. If remote
                    // attestation is used, the private key should not be
                    // supplied, since it needs to be generated inside an AWS
                    // Nitro enclave.
                    Some(match tls.key {
                        TlsKey::Path(ref key_path) => {
                            let key_bytes = std::fs::read_to_string(key_path).map_err(|e| {
                                anyhow::anyhow!("Failed to open file {}: {}", key_path.display(), e)
                            })?;
                            (
                                cert_pem,
                                x509_parser::pem::parse_x509_pem(key_bytes.as_ref())?.1,
                                None,
                            )
                        }
                        TlsKey::Pem(ref key_bytes) => (
                            cert_pem,
                            x509_parser::pem::parse_x509_pem(key_bytes.as_ref())?.1,
                            None,
                        ),
                        // When remote attestation is used, the enclave
                        // generates a self-signed TLS certificate for a private
                        // key that never leaves its memory. This certificate
                        // includes the AWS Nitro attestation document and the
                        // certificate used used by the MPC party to sign the
                        // enclave image it is running.
                        TlsKey::Enclave(EnclaveConf {
                            ref trusted_releases,
                        }) => {
                            match security_module {
                                Some(sm) => {
                                    tracing::info!("Using wrapped TLS certificate with Nitro remote attestation");
                                    let (cert, key) = sm.wrap_x509_cert(cert_pem).await?;
                                    (cert, key, Some(Arc::new(trusted_releases.clone())))
                                }
                                None => panic!(
                                "TLS certificate present but not private key or security module"
                            ),
                            }
                        }
                    })
                }
                None => {
                    tracing::warn!("No TLS identity - using plaintext communication");
                    None
                }
            };
            let (kms, health_service) = threshold_server_init(
                threshold_config,
                mpc_listener,
                public_vault,
                private_vault,
                backup_vault,
                tls_identity,
                false,
                core_config.rate_limiter_conf,
                std::future::pending(),
            )
            .await?;
            run_server(
                core_config.service,
                service_listener,
                Arc::new(kms),
                health_service,
                std::future::pending(),
            )
            .await?;
        }
        None => {
            let (kms, health_service) = RealCentralizedKms::new(
                public_vault,
                private_vault,
                backup_vault,
                core_config.rate_limiter_conf,
            )
            .await?;
            run_server(
                core_config.service,
                service_listener,
                Arc::new(kms),
                health_service,
                std::future::pending(),
            )
            .await?
        }
    }

    // Sleep to let some time for the process to export all the spans before exit
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Explicitly shut down telemetry to ensure all data is properly exported
    if let Err(e) = tracer_provider.shutdown() {
        eprintln!("Error shutting down tracer provider: {}", e);
    }

    if let Err(e) = meter_provider.shutdown() {
        eprintln!("Error shutting down meter provider: {}", e);
    }

    Ok(())
}
