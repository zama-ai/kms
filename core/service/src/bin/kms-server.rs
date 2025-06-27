use clap::Parser;
use futures_util::future::OptionFuture;
use k256::ecdsa::SigningKey;
use kms_grpc::rpc_types::PubDataType;
use kms_lib::{
    conf::{init_conf_kms_core_telemetry, threshold::TlsConf, CoreConfig},
    consts::SIGNING_KEY_ID,
    cryptography::attestation::{make_security_module, SecurityModule},
    engine::{
        centralized::central_kms::RealCentralizedKms, run_server,
        threshold::service::new_real_threshold_kms,
    },
    vault::{
        aws::build_aws_sdk_config,
        keychain::{awskms::build_aws_kms_client, make_keychain},
        storage::{
            crypto_material::get_core_signing_key, make_storage, read_text_at_request_id,
            s3::build_s3_client, StorageCache, StorageType,
        },
        Vault,
    },
};
use std::{net::ToSocketAddrs, sync::Arc};
use threshold_fhe::{execution::runtime::party::Role, networking::tls::BasicTLSConfig};
use tokio::net::TcpListener;

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
        init_conf_kms_core_telemetry::<CoreConfig>(&args.config_file).await?;

    tracing::info!("Starting KMS Server with core config: {:?}", &core_config);

    let party_role = core_config
        .threshold
        .as_ref()
        .map(|t| Role::indexed_from_one(t.my_id));

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
        .map(|v| v.storage.is_s_3())
        .unwrap_or(false)
        || core_config
            .private_vault
            .as_ref()
            .map(|v| v.storage.is_s_3())
            .unwrap_or(false)
        || core_config
            .backup_vault
            .as_ref()
            .map(|v| v.storage.is_s_3())
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
        .and_then(|v| v.keychain.as_ref().map(|k| k.is_aws_kms()))
        .unwrap_or(false)
        || core_config
            .backup_vault
            .as_ref()
            .and_then(|v| v.keychain.as_ref().map(|k| k.is_aws_kms()))
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

    // security module (used for remote attestation with AWS KMS or mTLS)
    let need_security_module = need_awskms_client
        || core_config
            .threshold
            .as_ref()
            .and_then(|t| t.tls.as_ref())
            .map(|tls| tls.is_semi_auto() || tls.is_full_auto())
            .unwrap_or(false);
    let security_module = need_security_module
        .then(make_security_module)
        .transpose()
        .inspect_err(|e| tracing::warn!("Could not initialize security module: {e}"))?;

    // public vault
    let public_storage = make_storage(
        core_config.public_vault.map(|v| v.storage),
        StorageType::PUB,
        party_role,
        public_storage_cache,
        s3_client.clone(),
    )
    .inspect_err(|e| tracing::warn!("Could not initialize public storage: {e}"))?;
    let public_vault = Vault {
        storage: public_storage,
        keychain: None,
    };

    // private vault
    let private_storage = make_storage(
        core_config
            .private_vault
            .as_ref()
            .map(|v| v.storage.clone()),
        StorageType::PRIV,
        party_role,
        private_storage_cache,
        s3_client.clone(),
    )
    .inspect_err(|e| tracing::warn!("Could not private storage: {e}"))?;
    let private_keychain = OptionFuture::from(
        core_config
            .private_vault
            .as_ref()
            .and_then(|v| v.keychain.as_ref())
            .map(|k| {
                make_keychain(
                    k,
                    awskms_client.clone(),
                    security_module.clone(),
                    None,
                    None,
                    None,
                )
            }),
    )
    .await
    .transpose()
    .inspect_err(|e| tracing::warn!("Could not initialize private keychain: {e}"))?;
    let private_vault = Vault {
        storage: private_storage,
        keychain: private_keychain,
    };

    // load signing key
    let sk = get_core_signing_key(&private_vault).await?;

    // compute corresponding public key and derive address from private sig key
    let pk = SigningKey::verifying_key(sk.sk());
    tracing::info!(
        "Public ethereum address is {}",
        alloy_signer::utils::public_key_to_address(pk)
    );

    // backup vault (unlike for private/public storage, there cannot be a
    // default location for backup storage, so there has to be
    // Some(storage_url))
    let backup_storage = core_config
        .backup_vault
        .as_ref()
        .map(|v| {
            make_storage(
                Some(v.storage.clone()),
                StorageType::BACKUP,
                party_role,
                None,
                s3_client,
            )
        })
        .transpose()
        .inspect_err(|e| tracing::warn!("Could not initialize backup storage: {e}"))?;
    let backup_keychain = OptionFuture::from(
        core_config
            .backup_vault
            .as_ref()
            .and_then(|v| v.keychain.as_ref())
            .map(|k| {
                make_keychain(
                    k,
                    awskms_client.clone(),
                    security_module.clone(),
                    Some(&public_vault),
                    party_role,
                    Some(sk.clone()),
                )
            }),
    )
    .await
    .transpose()
    .inspect_err(|e| tracing::warn!("Could not initialize backup keychain: {e}"))?;
    let backup_vault = backup_storage.map(|storage| Vault {
        storage,
        keychain: backup_keychain,
    });

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

    println!("KMS Server service socket address: {service_socket_addr}");

    let service_listener = TcpListener::bind(service_socket_addr)
        .await
        .unwrap_or_else(|e| panic!("Could not bind to {service_socket_addr} \n {e:?}"));

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
                .unwrap_or_else(|e| panic!("Could not bind to {mpc_socket_addr} \n {e:?}"));

            tracing::info!(
                "Starting threshold KMS server v{} for party {}, listening for MPC communication on {:?}...",
                env!("CARGO_PKG_VERSION"),
                threshold_config.my_id,
                mpc_socket_addr
            );
            tracing::info!(
                "Parameters: using threshold t={}, knowing n={} parties in total (myself included)",
                threshold_config.threshold,
                threshold_config.peers.len()
            );

            // Communication between MPC parties can be optionally protected
            // with mTLS which requires a TLS certificate valid both for server
            // and client authentication.
            let tls_identity = match threshold_config.tls {
                Some(TlsConf::Manual { ref cert, ref key }) => {
                    let cert =
                        cert.into_pem(threshold_config.my_id, threshold_config.peers.as_slice())?;
                    let key = key.into_pem()?;
                    Some(BasicTLSConfig {
                        cert,
                        key,
                        trusted_releases: None,
                        pcr8_expected: false,
                    })
                }
                // When remote attestation is used, the enclave generates a
                // self-signed TLS certificate for a private key that never
                // leaves its memory. This certificate includes the AWS
                // Nitro attestation document and the certificate used
                // by the MPC party to sign the enclave image it is
                // running. The private key is not supplied, since it needs
                // to be generated inside an AWS Nitro enclave.
                Some(TlsConf::SemiAuto {
                    ref cert,
                    ref trusted_releases,
                }) => {
                    let security_module = security_module.unwrap_or_else(|| {
                            panic!("EIF signing certificate present but not security module, unable to construct TLS identity")
                        });
                    tracing::info!("Using wrapped TLS certificate with Nitro remote attestation");
                    let eif_signing_cert_pem =
                        cert.into_pem(threshold_config.my_id, threshold_config.peers.as_slice())?;
                    let (cert, key) = security_module.wrap_x509_cert(eif_signing_cert_pem).await?;
                    Some(BasicTLSConfig {
                        cert,
                        key,
                        trusted_releases: Some(Arc::new(trusted_releases.clone())),
                        pcr8_expected: true,
                    })
                }
                Some(TlsConf::FullAuto {
                    ref trusted_releases,
                }) => {
                    let security_module = security_module
                        .unwrap_or_else(|| panic!("TLS identity and security module not present"));
                    tracing::info!(
                        "Using TLS certificate with Nitro remote attestation signed by onboard CA"
                    );
                    let ca_cert_bytes = read_text_at_request_id(
                        &public_vault,
                        &SIGNING_KEY_ID,
                        &PubDataType::CACert.to_string(),
                    )
                    .await?;
                    let ca_cert = x509_parser::pem::parse_x509_pem(ca_cert_bytes.as_bytes())?.1;

                    let (cert, key) = security_module.issue_x509_cert(ca_cert, &sk).await?;
                    Some(BasicTLSConfig {
                        cert,
                        key,
                        trusted_releases: Some(Arc::new(trusted_releases.clone())),
                        pcr8_expected: false,
                    })
                }
                None => {
                    tracing::warn!("No TLS identity - using plaintext communication");
                    None
                }
            };
            let (kms, health_service) = new_real_threshold_kms(
                threshold_config,
                public_vault,
                private_vault,
                backup_vault,
                mpc_listener,
                sk,
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
            tracing::info!(
                "Starting centralized KMS server v{}...",
                env!("CARGO_PKG_VERSION"),
            );
            let (kms, health_service) = RealCentralizedKms::new(
                public_vault,
                private_vault,
                backup_vault,
                sk,
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
        eprintln!("Error shutting down tracer provider: {e}");
    }

    if let Err(e) = meter_provider.shutdown() {
        eprintln!("Error shutting down meter provider: {e}");
    }

    Ok(())
}
