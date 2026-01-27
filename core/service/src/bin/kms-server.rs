use anyhow::ensure;
use clap::Parser;
use futures_util::future::OptionFuture;
use kms_grpc::rpc_types::{KMSType, PubDataType};
use kms_lib::{
    conf::{
        init_conf, init_conf_kms_core_telemetry,
        threshold::{PeerConf, ThresholdPartyConf, TlsConf},
        CoreConfig,
    },
    consts::{DEFAULT_MPC_CONTEXT, SIGNING_KEY_ID},
    cryptography::{
        attestation::{
            make_security_module, AutoRefreshCertResolver, CertResolver, SecurityModuleProxy,
        },
        signatures::PrivateSigKey,
    },
    engine::{
        base::BaseKmsStruct, centralized::central_kms::RealCentralizedKms,
        context_manager::create_default_centralized_context_in_storage,
        migration::migrate_fhe_keys_v0_12_to_v0_13, run_server,
        threshold::service::new_real_threshold_kms,
    },
    grpc::MetaStoreStatusServiceImpl,
    vault::{
        aws::build_aws_sdk_config,
        keychain::{
            awskms::build_aws_kms_client, make_keychain_proxy, Keychain, RootKeyMeasurements,
        },
        storage::{
            crypto_material::get_core_signing_key, make_storage, read_text_at_request_id,
            s3::build_s3_client, StorageCache, StorageReader, StorageType,
        },
        Vault,
    },
};
use std::{env, net::ToSocketAddrs, sync::Arc, thread};
use threshold_fhe::{
    networking::tls::{build_ca_certs_map, AttestedVerifier},
    thread_handles::init_rayon_thread_pool,
};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{
    client::{danger::DangerousClientConfigBuilder, ClientConfig},
    crypto::{aws_lc_rs::default_provider as aws_lc_rs_default_provider, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer},
    server::ServerConfig,
    sign::{CertifiedKey, SingleCertAndKey},
    version::TLS13,
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
    #[clap(
        long,
        default_value_t = false,
        help = "ignore the peerlist from the configuration file"
    )]
    ignore_peerlist: bool,
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
        "Starting threshold KMS server v{}, with id {:?}, listening for MPC communication on {:?}...",
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
#[allow(clippy::too_many_arguments)]
async fn build_tls_config(
    peers: &Option<Vec<PeerConf>>,
    tls_config: &TlsConf,
    security_module: Option<Arc<SecurityModuleProxy>>,
    private_vault_root_key_measurements: Option<Arc<RootKeyMeasurements>>,
    public_vault: &Vault,
    sk: Arc<PrivateSigKey>,
    #[cfg(feature = "insecure")] mock_enclave: bool,
) -> anyhow::Result<(ServerConfig, ClientConfig, Arc<AttestedVerifier>)> {
    let verf_key = sk.verf_key();
    let context_id = *DEFAULT_MPC_CONTEXT;
    aws_lc_rs_default_provider()
        .install_default()
        .unwrap_or_else(|_| {
            panic!("Failed to load default crypto provider");
        });
    let crypto_provider = CryptoProvider::get_default()
        .ok_or_else(|| anyhow::anyhow!("rustls cryptoprovider not initialized"))?;
    // Communication between MPC parties can be optionally protected
    // with mTLS which requires a TLS certificate valid both for server
    // and client authentication.
    let (ca_certs_list, my_peer) = match peers {
        Some(peers) => {
            let cert_list = peers
                .iter()
                .map(|peer| {
                    peer.tls_cert
                        .as_ref()
                        .map(|cert| cert.into_pem_with_sanity_check(peer.party_id, peers))
                        .unwrap_or_else(|| {
                            panic!("No CA certificate present for peer {}", peer.party_id)
                        })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            let myself = peers
                .iter()
                .find(|p| p.verification_address == Some(verf_key.address()));
            (cert_list, myself)
        }
        None => (vec![], None),
    };

    // NOTE: ca_certs can be empty if peerlist is not set
    let ca_certs = build_ca_certs_map(ca_certs_list.into_iter())?;

    let (
        cert_resolver,
        trusted_releases,
        pcr8_expected,
        ignore_aws_ca_chain,
        attest_private_vault_root_key,
    ) = match tls_config {
        TlsConf::Manual { ref cert, ref key } => {
            tracing::info!("Using third-party TLS certificate without Nitro remote attestation");
            let cert = match my_peer {
                Some(peer) => cert.into_pem(peer)?,
                None => {
                    tracing::info!(
                        "Cannot find a peer that corresponds to myself, skipping TLS certificate validation against peerlist"
                    );
                    cert.unchecked_pem()?
                }
            };
            let key = key.into_pem()?;
            let cert_resolver = Arc::new(CertResolver::Single(SingleCertAndKey::from(
                CertifiedKey::from_der(
                    vec![CertificateDer::from_slice(cert.contents.as_slice()).into_owned()],
                    PrivateKeyDer::try_from(key.contents.as_slice())
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                        .clone_key(),
                    crypto_provider,
                )?,
            )));
            (cert_resolver, None, false, false, false)
        }

        // When remote attestation is used, the enclave generates a
        // self-signed TLS certificate for a private key that never
        // leaves its memory. This certificate includes the AWS
        // Nitro attestation document and the certificate used
        // by the MPC party to sign the enclave image it is
        // running. The private key is not supplied, since it needs
        // to be generated inside an AWS Nitro enclave.
        TlsConf::Auto {
            ref eif_signing_cert,
            ref trusted_releases,
            ref ignore_aws_ca_chain,
            ref attest_private_vault_root_key,
            ref renew_slack_after_expiration,
            ref renew_fail_retry_timeout,
        } => {
            let security_module = security_module
                .as_ref()
                .unwrap_or_else(|| panic!("TLS identity and security module not present"));
            let (sk, ca_cert) = match eif_signing_cert {
                Some(eif_signing_cert) => {
                    tracing::info!("Using wrapped TLS certificate with Nitro remote attestation");
                    (
                        None,
                        match my_peer {
                            Some(peer) => eif_signing_cert.into_pem(peer)?,
                            None => {
                                tracing::info!(
                                    "No peerlist present, skipping TLS certificate validation against peerlist"
                                );
                                eif_signing_cert.unchecked_pem()?
                            }
                        },
                    )
                }
                None => {
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

                    // check if the CA certificate matches the KMS signing key
                    let ca_cert_x509 = ca_cert.parse_x509()?;
                    if let x509_parser::public_key::PublicKey::EC(pk_sec1) =
                        ca_cert_x509.public_key().parsed()?
                    {
                        let ca_pk = Box::new(pk_sec1.data());
                        #[allow(deprecated)]
                        let sk_vk = sk.sk().verifying_key().to_encoded_point(false).to_bytes();
                        ensure!(
                    **ca_pk == *sk_vk,
                    "CA certificate public key {:?} doesn't correspond to the KMS verifying key {:?}",
                    hex::encode(*ca_pk),
                    hex::encode(sk_vk)
                        );
                    } else {
                        panic!("CA certificate public key isn't ECDSA");
                    };
                    (Some(sk), ca_cert)
                }
            };

            let attest_private_vault_root_key_flag =
                attest_private_vault_root_key.is_some_and(|m| m);

            let cert_resolver = Arc::new(CertResolver::AutoRefresh(
                AutoRefreshCertResolver::new(
                    sk,
                    ca_cert,
                    security_module.clone(),
                    if attest_private_vault_root_key_flag {
                        private_vault_root_key_measurements
                    } else {
                        None
                    },
                    renew_slack_after_expiration.unwrap_or(5),
                    renew_fail_retry_timeout.unwrap_or(60),
                )
                .await?,
            ));

            (
                cert_resolver,
                Some(trusted_releases.iter().cloned().collect()),
                eif_signing_cert.is_some(),
                ignore_aws_ca_chain.is_some_and(|m| m),
                attest_private_vault_root_key_flag,
            )
        }
    };

    let verifier = Arc::new(AttestedVerifier::new(
        if attest_private_vault_root_key {
            Some(Arc::new(
                kms_lib::vault::keychain::verify_root_key_measurements,
            ))
        } else {
            None
        },
        pcr8_expected,
        #[cfg(feature = "insecure")]
        mock_enclave,
        ignore_aws_ca_chain,
    )?);
    // Adding a context to the verifier is optional at this point and
    // can be done at any point of the application lifecycle, for
    // example, when a new context is set through a GRPC call.
    verifier.add_context(context_id.derive_session_id()?, ca_certs, trusted_releases)?;

    let server_config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier.clone())
        .with_cert_resolver(cert_resolver.clone());
    let client_config = DangerousClientConfigBuilder {
        cfg: ClientConfig::builder_with_protocol_versions(&[&TLS13]),
    }
    .with_custom_certificate_verifier(verifier.clone())
    .with_client_cert_resolver(cert_resolver.clone());
    Ok((server_config, client_config, verifier))
}

fn main() -> anyhow::Result<()> {
    let args = KmsArgs::parse();
    // NOTE: this config is only needed to set up the tokio runtime
    // we read it again in [main_exec] to set up the rest of the server
    let core_config = init_conf::<CoreConfig>(&args.config_file)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(
            core_config
                .internal_config
                .unwrap_or_default()
                .num_tokio_threads,
        )
        .build()?;
    rt.block_on(main_exec())
}

/// Starts a KMS server.
/// We support two execution modes, `centralized` or `threshold`, that have to be specified with the `mode` parameter in the configuration file.
/// See the help page for additional details.
/// Note that key material MUST exist when starting the server and be stored in the path specified by the configuration file.
/// Please consult the `kms-gen-keys` binary for details on generating key material.
async fn main_exec() -> anyhow::Result<()> {
    let args = KmsArgs::parse();
    let (mut core_config, tracer_provider, meter_provider) =
        init_conf_kms_core_telemetry::<CoreConfig>(&args.config_file).await?;
    if let Some(t) = core_config.threshold.as_mut() {
        if args.ignore_peerlist {
            tracing::warn!(
                "Ignoring peerlist from configuration file as per command line argument"
            );
            t.peers = None;
        }
    };

    // Initialize the rayon pool used inside MPC protocols
    let num_rayon_threads = init_rayon_thread_pool(
        core_config
            .internal_config
            .clone()
            .unwrap_or_default()
            .num_rayon_threads,
    )
    .await?;

    tracing::info!("Starting KMS Server with core config: {:?}", &core_config);

    tracing::info!(
        "Multi-threading values: tokio::num_workers: {}, rayon_num_threads: {}, total_num_cpus: {}",
        tokio::runtime::Handle::current().metrics().num_workers(),
        num_rayon_threads,
        thread::available_parallelism()?.get(),
    );

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
                core_config
                    .aws
                    .as_ref()
                    .and_then(|aws| aws.awskms_endpoint.clone()),
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
            .map(|tls| tls.is_auto())
            .unwrap_or(false);
    let security_module = need_security_module
        .then(|| {
            make_security_module(
                #[cfg(feature = "insecure")]
                core_config.mock_enclave.is_some_and(|m| m),
            )
        })
        .transpose()
        .inspect_err(|e| tracing::warn!("Could not initialize security module: {e}"))?
        .map(Arc::new);

    // public vault
    let public_storage_conf = core_config.public_vault.as_ref().map(|v| v.storage.clone());
    let public_storage = make_storage(
        public_storage_conf,
        StorageType::PUB,
        public_storage_cache,
        s3_client.clone(),
    )
    .inspect_err(|e| tracing::warn!("Could not initialize public storage: {e}"))?;
    let public_vault = Vault {
        storage: public_storage.clone(),
        keychain: None,
    };

    // private vault
    let mut private_storage = make_storage(
        core_config
            .private_vault
            .as_ref()
            .map(|v| v.storage.clone()),
        StorageType::PRIV,
        private_storage_cache,
        s3_client.clone(),
    )
    .inspect_err(|e| tracing::warn!("Could not private storage: {e}"))?;

    // Migrate legacy FHE keys to epoch-aware format
    let kms_type = match core_config.threshold {
        Some(_) => KMSType::Threshold,
        None => KMSType::Centralized,
    };
    migrate_fhe_keys_v0_12_to_v0_13(&mut private_storage, kms_type)
        .await
        .inspect_err(|e| tracing::warn!("Could not migrate legacy FHE keys: {e}"))?;

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
                    security_module.as_ref().map(Arc::clone),
                    Some(&public_vault.storage),
                )
            }),
    )
    .await
    .transpose()
    .inspect_err(|e| tracing::warn!("Could not initialize private keychain: {e}"))?;
    let mut private_vault = Vault {
        storage: private_storage,
        keychain: private_keychain,
    };

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
                    security_module.as_ref().map(Arc::clone),
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

    // load key
    let base_kms = match get_core_signing_key(&private_vault).await {
        Ok(sk) => BaseKmsStruct::new(kms_type, sk)?,
        Err(e) => {
            tracing::warn!("Error loading signing key: {e:?}");
            tracing::warn!(
                "SIGNING KEY NOT AVAILABLE, ENTERING RECOVERY MODE!!!!\nOnly backup recovery operations should be done as TLS is not available!\n
                Make sure to validate that the current verification key in public storage is EXACTLY equal to the one on the gateway before proceeding!"
            );
            let verf_key = public_storage
                .read_data(&SIGNING_KEY_ID, &PubDataType::VerfKey.to_string())
                .await?;
            BaseKmsStruct::new_no_signing_key(kms_type, verf_key)
        }
    };

    // compute corresponding public key and derive address from private sig key
    #[allow(deprecated)]
    let pk_bytes = base_kms.verf_key().pk().to_encoded_point(false).to_bytes();
    tracing::info!("KMS verifying key is {}", hex::encode(pk_bytes));
    tracing::info!(
        "Public ethereum address is {}",
        base_kms.verf_key().address()
    );

    match core_config.threshold {
        Some(ref threshold_config) => {
            let mpc_listener = make_mpc_listener(threshold_config).await;

            let tls_identity = match &threshold_config.tls {
                Some(tls_config) => Some({
                    build_tls_config(
                        &threshold_config.peers,
                        tls_config,
                        security_module.clone(),
                        private_vault
                            .keychain
                            .as_ref()
                            .map(|x| x.root_key_measurements()),
                        &public_vault,
                        base_kms.sig_key()?,
                        #[cfg(feature = "insecure")]
                        core_config.mock_enclave.is_some_and(|m| m),
                    )
                    .await?
                }),
                None => {
                    tracing::warn!(
                        "No TLS identity - using plaintext communication between MPC nodes"
                    );
                    None
                }
            };

            #[cfg(not(feature = "insecure"))]
            let need_peer_tcp_proxy = need_security_module;
            #[cfg(feature = "insecure")]
            let need_peer_tcp_proxy =
                need_security_module && !core_config.mock_enclave.is_some_and(|m| m);

            if need_peer_tcp_proxy {
                tracing::warn!("KMS server will connect to peers through vsock proxies");
            } else {
                tracing::warn!("KMS server will connect to peers directly");
            };
            let service_config = core_config.service.clone();
            let (kms, health_service, metastore_status_service) = new_real_threshold_kms(
                core_config,
                public_vault,
                private_vault,
                backup_vault,
                security_module,
                mpc_listener,
                base_kms,
                tls_identity,
                need_peer_tcp_proxy,
                false,
                std::future::pending(),
            )
            .await?;
            let meta_store_status_service = Arc::new(metastore_status_service);
            tracing::info!(
                "Starting threshold KMS server v{}...",
                env!("CARGO_PKG_VERSION"),
            );
            run_server(
                service_config,
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
            // create the default context if it does not exist
            let sk = (*base_kms.sig_key()?).clone();
            create_default_centralized_context_in_storage(&mut private_vault, &sk).await?;
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
