use clap::Parser;
use futures_util::future::OptionFuture;
use k256::ecdsa::SigningKey;
use kms_grpc::rpc_types::PubDataType;
use kms_lib::{
    conf::{
        init_conf_kms_core_telemetry,
        threshold::{PeerConf, ThresholdPartyConf, TlsConf},
        CoreConfig,
    },
    consts::{DEFAULT_MPC_CONTEXT, SIGNING_KEY_ID},
    cryptography::{
        attestation::{make_security_module, SecurityModule, SecurityModuleProxy},
        internal_crypto_types::PrivateSigKey,
    },
    engine::{
        centralized::central_kms::RealCentralizedKms, run_server,
        threshold::service::new_real_threshold_kms,
    },
    grpc::MetaStoreStatusServiceImpl,
    vault::{
        aws::build_aws_sdk_config,
        keychain::{awskms::build_aws_kms_client, make_keychain_proxy},
        storage::{
            crypto_material::get_core_signing_key, make_storage, read_text_at_request_id,
            s3::build_s3_client, StorageCache, StorageType,
        },
        Vault,
    },
};
use std::{env, net::ToSocketAddrs, sync::Arc, thread};
use threshold_fhe::{
    execution::runtime::party::Role,
    networking::tls::{build_ca_certs_map, AttestedVerifier},
};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{
    client::{danger::DangerousClientConfigBuilder, ClientConfig},
    crypto::aws_lc_rs::default_provider as aws_lc_rs_default_provider,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::ServerConfig,
};

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

async fn make_mpc_listener(threshold_config: &ThresholdPartyConf) -> TcpListener {
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
    if let Some(peers) = &threshold_config.peers {
        tracing::info!(
            "Parameters: using threshold t={}, knowing n={} parties in total (myself included)",
            threshold_config.threshold,
            peers.len()
        );
    }

    mpc_listener
}

/// Communication between MPC parties can be optionally protected with mTLS
/// which requires a TLS certificate valid both for server and client
/// authentication.  We have to construct rustls config structs ourselves
/// instead of using the wrapper from tonic::transport because we need to
/// provide our own certificate verifier that can validate bundled attestation
/// documents and that can receive new trust roots on the context change.
async fn build_tls_config(
    my_id: usize,
    peers: &[PeerConf],
    tls_config: &TlsConf,
    security_module: Option<SecurityModuleProxy>,
    public_vault: &Vault,
    sk: &PrivateSigKey,
) -> anyhow::Result<(ServerConfig, ClientConfig)> {
    let context_id = *DEFAULT_MPC_CONTEXT;
    aws_lc_rs_default_provider()
        .install_default()
        .unwrap_or_else(|_| {
            panic!("Failed to load default crypto provider");
        });
    // Communication between MPC parties can be optionally protected
    // with mTLS which requires a TLS certificate valid both for server
    // and client authentication.
    let ca_certs_list = peers
        .iter()
        .map(|peer| {
            peer.tls_cert
                .as_ref()
                .map(|cert| cert.into_pem(peer.party_id, peers))
                .unwrap_or_else(|| panic!("No CA certificate present for peer {}", peer.party_id))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let ca_certs = build_ca_certs_map(ca_certs_list.into_iter())?;

    let (cert, key, trusted_releases, pcr8_expected) = match tls_config {
        TlsConf::Manual { ref cert, ref key } => {
            tracing::info!("Using third-party TLS certificate without Nitro remote attestation");
            let cert = cert.into_pem(my_id, peers)?;
            let key = key.into_pem()?;
            (cert, key, None, false)
        }
        // When remote attestation is used, the enclave generates a
        // self-signed TLS certificate for a private key that never
        // leaves its memory. This certificate includes the AWS
        // Nitro attestation document and the certificate used
        // by the MPC party to sign the enclave image it is
        // running. The private key is not supplied, since it needs
        // to be generated inside an AWS Nitro enclave.
        TlsConf::SemiAuto {
            ref cert,
            ref trusted_releases,
        } => {
            let security_module = security_module.as_ref().unwrap_or_else(|| {
                            panic!("EIF signing certificate present but not security module, unable to construct TLS identity")
                        });
            tracing::info!("Using wrapped TLS certificate with Nitro remote attestation");
            let eif_signing_cert_pem = cert.into_pem(my_id, peers)?;
            let (cert, key) = security_module
                .wrap_x509_cert(context_id, eif_signing_cert_pem)
                .await?;
            (cert, key, Some(Arc::new(trusted_releases.clone())), true)
        }
        TlsConf::FullAuto {
            ref trusted_releases,
        } => {
            let security_module = security_module
                .as_ref()
                .unwrap_or_else(|| panic!("TLS identity and security module not present"));
            tracing::info!(
                "Using TLS certificate with Nitro remote attestation signed by onboard CA"
            );
            let ca_cert_bytes = read_text_at_request_id(
                public_vault,
                &SIGNING_KEY_ID,
                &PubDataType::CACert.to_string(),
            )
            .await?;
            let ca_cert = x509_parser::pem::parse_x509_pem(ca_cert_bytes.as_bytes())?.1;

            let (cert, key) = security_module
                .issue_x509_cert(context_id, ca_cert, sk)
                .await?;
            (cert, key, Some(Arc::new(trusted_releases.clone())), false)
        }
    };

    let cert_chain = vec![CertificateDer::from_slice(cert.contents.as_slice()).into_owned()];
    let key_der = PrivateKeyDer::try_from(key.contents.as_slice())
        .unwrap_or_else(|e| panic!("Could not read TLS private key: {e}"))
        .clone_key();
    let verifier = Arc::new(AttestedVerifier::new(pcr8_expected)?);
    // Adding a context to the verifier is optional at this point and
    // can be done at any point of the application lifecycle, for
    // example, when a new context is set through a GRPC call.
    verifier.add_context(context_id.derive_session_id()?, ca_certs, trusted_releases)?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(cert_chain.clone(), key_der.clone_key())?;
    let client_config = DangerousClientConfigBuilder {
        cfg: ClientConfig::builder(),
    }
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(cert_chain, key_der)?;
    Ok((server_config, client_config))
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

    tracing::info!(
        "Multi-threading ENV vars: Tokio {:?}; Rayon {:?}; available_parallelism: {}, rayon::max_num_threads: {}, tokio::num_workers: {}.",
        env::var_os("TOKIO_WORKER_THREADS"),
        env::var_os("RAYON_NUM_THREADS"),
        thread::available_parallelism()?.get(),
        rayon::current_num_threads(),
        tokio::runtime::Handle::current().metrics().num_workers()
    );

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
                // Observe that the public storage is used to load a backup_id and backup key
                // in the case where the custodian based secret sharing is used
                make_keychain_proxy(
                    k,
                    awskms_client.clone(),
                    security_module.clone(),
                    Some(&public_vault.storage),
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
                make_keychain_proxy(
                    k,
                    awskms_client.clone(),
                    security_module.clone(),
                    Some(&public_vault),
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
            let mpc_listener = make_mpc_listener(&threshold_config).await;
            let tls_identity = match &threshold_config.tls {
                Some(tls_config) => Some(match &threshold_config.peers {
                    Some(peers) => {
                        build_tls_config(
                            threshold_config.my_id,
                            peers,
                            tls_config,
                            security_module.clone(),
                            &public_vault,
                            &sk,
                        )
                        .await?
                    }
                    None => {
                        panic!("TLS enabled but peer list not provided: reading peer list from the context unsupported yet")
                    }
                }),
                None => {
                    tracing::warn!(
                        "No TLS identity - using plaintext communication between MPC nodes"
                    );
                    None
                }
            };

            let (kms, health_service, metastore_status_service) = new_real_threshold_kms(
                threshold_config,
                public_vault,
                private_vault,
                backup_vault,
                security_module,
                mpc_listener,
                sk,
                tls_identity,
                need_security_module,
                false,
                core_config.rate_limiter_conf,
                std::future::pending(),
            )
            .await?;
            let meta_store_status_service = Arc::new(metastore_status_service);
            run_server(
                core_config.service,
                service_listener,
                Arc::new(kms),
                meta_store_status_service,
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
                security_module,
                sk,
                core_config.rate_limiter_conf,
            )
            .await?;
            let meta_store_status_service = Arc::new(MetaStoreStatusServiceImpl::new(
                Some(Arc::clone(kms.get_key_gen_meta_store())), // key_gen_store
                Some(Arc::clone(kms.get_pub_dec_meta_store())), // pub_dec_store
                Some(Arc::clone(kms.get_user_dec_meta_store())), // user_dec_store
                Some(Arc::clone(kms.get_crs_meta_store())),     // crs_store
                None, // preproc_store - not available in centralized mode
                Some(Arc::clone(kms.get_custodian_meta_store())), // custodian_store
            ));
            run_server(
                core_config.service,
                service_listener,
                Arc::new(kms),
                meta_store_status_service,
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
