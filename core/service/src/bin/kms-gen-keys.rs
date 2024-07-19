use clap::{Parser, Subcommand};
use kms_lib::conf::init_trace;
use kms_lib::rpc::rpc_types::{PrivDataType, PubDataType};
use kms_lib::util::key_setup::test_tools::ensure_threshold_keys_exist;
use kms_lib::{
    consts::{
        AMOUNT_PARTIES, DEFAULT_CENTRAL_KEY_ID, DEFAULT_CRS_ID, DEFAULT_THRESHOLD_KEY_ID,
        OTHER_CENTRAL_DEFAULT_ID,
    },
    storage::{url_to_pathbuf, FileStorage, Storage, StorageReader, StorageType},
    util::{
        aws::S3Storage,
        key_setup::{
            ensure_central_crs_store_exists, ensure_central_keys_exist,
            ensure_central_server_signing_keys_exist,
        },
    },
    StorageProxy,
};
use strum::IntoEnumIterator;

#[derive(Parser)]
#[clap(name = "Zama KMS Key Material Generator")]
#[clap(about = "A CLI tool for generating key materials. \
    In the centralized mode, it will generate FHE keys, signing keys and the CRS. \
    In the threshold mode, it will generate FHE key shares and the signing keys, \
    the FHE key shares should be used for testing only. \
    Use the threshold protocols to generate FHE key shares. \
    But observe that threshold mode should only be used for testing since keys will get generated centrally. \n
    For example, to generate centralized keys with the default parameters \
    (from parameters/default_params.json) run: \n
    ./kms-gen-keys centralized \n
    Multiple options are supported which can be explored with \
    kms-key-gen --help")]
struct Args {
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Clone, Subcommand)]
enum Mode {
    /// Generate centralized FHE keys, signing keys and the CRS.
    Centralized {
        /// Path to the parameters file.
        #[clap(long, default_value = "parameters/default_params.json")]
        param_path: String,
        /// AWS region to use for S3 storage
        #[clap(long, default_value = "eu-west-3")]
        aws_region: String,
        /// Optional parameter for the private storage URL
        #[clap(long, default_value = None)]
        priv_url: Option<String>,
        /// Optional parameter for the public storage URL
        #[clap(long, default_value = None)]
        pub_url: Option<String>,
        /// Whether to generate keys deterministically,
        /// only use this option for testing.
        /// The determinism is not guaranteed to be the same between releases.
        #[clap(long, default_value_t = false)]
        deterministic: bool,
        /// Whether to overwrite ALL the existing keys,
        #[clap(long, default_value_t = false)]
        overwrite: bool,
        /// Whether to output the private FHE key separately,
        #[clap(long, default_value_t = false)]
        write_privkey: bool,
        /// Only show existing keys, do not generate any
        #[clap(long, default_value_t = false)]
        show_existing: bool,
    },

    /// Generate shares of FHE key shares and signing keys.
    /// The FHE key shares should only be used for testing.
    /// At the moment it's only limited to 4 parties.
    Threshold {
        /// Path to the parameters file
        #[clap(long, default_value = "parameters/default_params.json")]
        param_path: String,
        /// AWS region to use for S3 storage
        #[clap(long, default_value = "eu-west-3")]
        aws_region: String,
        /// Optional parameter for the private storage URL
        #[clap(long, default_value = None)]
        priv_url: Option<String>,
        /// Optional parameter for the public storage URL
        #[clap(long, default_value = None)]
        pub_url: Option<String>,
        /// Whether to generate keys deterministically,
        /// only use this option for testing.
        /// The determinism is not guaranteed to be the same between releases.
        #[clap(long, default_value_t = false)]
        deterministic: bool,
        /// Whether to overwrite the existing keys,
        #[clap(long, default_value_t = false)]
        overwrite: bool,
        /// Only show existing keys, do not generate any
        #[clap(long, default_value_t = false)]
        show_existing: bool,
    },
}

/// Execute the KMS key generation
/// Key generation is supported for 2 different modes; centralized and threshold.
/// However, the threshold mode should only be used for testing since keys will get generated centrally.
///
/// For example, to generate centralized keys with the default parameters
/// (from parameters/default_params.json) run:
/// ```
/// ./kms-gen-keys centralized
/// ```
/// Or from cargo:
/// ```
/// cargo run --bin kms-gen-keys centralized
/// ```
/// Multiple options are supported which can be explored with
/// ```
/// ./kms-key-gen --help
/// ```
#[tokio::main]
async fn main() {
    init_trace().unwrap();
    let args = Args::parse();
    match args.mode {
        Mode::Centralized {
            param_path,
            aws_region,
            priv_url,
            pub_url,
            deterministic,
            overwrite,
            write_privkey,
            show_existing,
        } => {
            let pub_url = pub_url
                .as_deref()
                .map(url::Url::parse)
                .transpose()
                .expect("Could not parse public storage URL");
            let priv_url = priv_url
                .as_deref()
                .map(url::Url::parse)
                .transpose()
                .expect("Could not parse private storage URL");
            let mut pub_storage: StorageProxy = match pub_url {
                Some(url) => match url.scheme() {
                    "s3" => {
                        let blob_key_prefix = S3Storage::centralized_prefix(
                            Some(url.path().trim_start_matches('/').to_string()),
                            StorageType::PUB,
                        );
                        let mut storage = StorageProxy::S3(
                            S3Storage::new(
                                aws_region.clone(),
                                None,
                                url.host_str().unwrap().to_string(),
                                blob_key_prefix.clone(),
                            )
                            .await,
                        );
                        if overwrite {
                            let urls = storage.all_urls(blob_key_prefix.as_str()).await.unwrap();
                            for url in urls.values() {
                                storage.delete_data(url).await.unwrap();
                            }
                        }
                        storage
                    }
                    _ => {
                        let optional_path = url_to_pathbuf(&url);
                        if overwrite {
                            FileStorage::purge_centralized(
                                Some(optional_path.as_path()),
                                StorageType::PUB,
                            )
                            .unwrap();
                        }
                        StorageProxy::File(
                            FileStorage::new_centralized(
                                Some(optional_path.as_path()),
                                StorageType::PUB,
                            )
                            .unwrap(),
                        )
                    }
                },
                None => {
                    if overwrite {
                        FileStorage::purge_centralized(None, StorageType::PUB).unwrap();
                    }
                    StorageProxy::File(
                        FileStorage::new_centralized(None, StorageType::PUB).unwrap(),
                    )
                }
            };
            let mut priv_storage = match priv_url {
                Some(url) => match url.scheme() {
                    "s3" => {
                        let blob_key_prefix = S3Storage::centralized_prefix(
                            Some(url.path().trim_start_matches('/').to_string()),
                            StorageType::PRIV,
                        );
                        let mut storage = StorageProxy::S3(
                            S3Storage::new(
                                aws_region.clone(),
                                None,
                                url.host_str().unwrap().to_string(),
                                blob_key_prefix.clone(),
                            )
                            .await,
                        );
                        if overwrite {
                            let urls = storage.all_urls(blob_key_prefix.as_str()).await.unwrap();
                            for url in urls.values() {
                                storage.delete_data(url).await.unwrap();
                            }
                        }
                        storage
                    }
                    _ => {
                        let optional_path = url_to_pathbuf(&url);
                        if overwrite {
                            FileStorage::purge_centralized(
                                Some(optional_path.as_path()),
                                StorageType::PRIV,
                            )
                            .unwrap();
                        }
                        StorageProxy::File(
                            FileStorage::new_centralized(
                                Some(optional_path.as_path()),
                                StorageType::PRIV,
                            )
                            .unwrap(),
                        )
                    }
                },
                None => {
                    if overwrite {
                        FileStorage::purge_centralized(None, StorageType::PRIV).unwrap();
                    }
                    StorageProxy::File(
                        FileStorage::new_centralized(None, StorageType::PRIV).unwrap(),
                    )
                }
            };
            if show_existing {
                show_keys(&pub_storage, &priv_storage).await;
                return;
            }
            if !ensure_central_server_signing_keys_exist(
                &mut pub_storage,
                &mut priv_storage,
                deterministic,
            )
            .await
            {
                tracing::warn!("Signing keys already exist, skipping generation");
            }
            if !ensure_central_keys_exist(
                &mut pub_storage,
                &mut priv_storage,
                &param_path,
                &DEFAULT_CENTRAL_KEY_ID,
                &OTHER_CENTRAL_DEFAULT_ID,
                deterministic,
                write_privkey,
            )
            .await
            {
                tracing::warn!(
                    "FHE keys with default ID {} already exist, skipping generation",
                    DEFAULT_CENTRAL_KEY_ID.to_string()
                );
            }
            if !ensure_central_crs_store_exists(
                &mut pub_storage,
                &mut priv_storage,
                &param_path,
                &DEFAULT_CRS_ID,
                deterministic,
            )
            .await
            {
                tracing::warn!(
                    "CRS with default ID {} already exist, skipping generation",
                    DEFAULT_CRS_ID.to_string()
                );
            }

            tracing::info!(
                "Default centralized keys written based on parameters stored in {}",
                param_path
            );
        }
        Mode::Threshold {
            param_path,
            aws_region,
            priv_url,
            pub_url,
            deterministic,
            overwrite,
            show_existing,
        } => {
            let pub_url = pub_url
                .as_deref()
                .map(url::Url::parse)
                .transpose()
                .expect("Could not parse public storage URL");
            let priv_url = priv_url
                .as_deref()
                .map(url::Url::parse)
                .transpose()
                .expect("Could not parse private storage URL");
            let mut pub_storages = Vec::with_capacity(AMOUNT_PARTIES);
            for i in 1..=AMOUNT_PARTIES {
                match pub_url {
                    Some(ref url) => match url.scheme() {
                        "s3" => {
                            let blob_key_prefix = S3Storage::threshold_prefix(
                                Some(url.path().trim_start_matches('/').to_string()),
                                StorageType::PUB,
                                i,
                            );
                            let mut storage = StorageProxy::S3(
                                S3Storage::new(
                                    aws_region.clone(),
                                    None,
                                    url.host_str().unwrap().to_string(),
                                    blob_key_prefix.clone(),
                                )
                                .await,
                            );
                            if overwrite {
                                let urls =
                                    storage.all_urls(blob_key_prefix.as_str()).await.unwrap();
                                for url in urls.values() {
                                    storage.delete_data(url).await.unwrap();
                                }
                            }
                            pub_storages.push(storage);
                        }
                        _ => {
                            let optional_path = url_to_pathbuf(url);
                            if overwrite {
                                FileStorage::purge_threshold(
                                    Some(optional_path.as_path()),
                                    StorageType::PUB,
                                    i,
                                )
                                .unwrap();
                            }
                            pub_storages.push(StorageProxy::File(
                                FileStorage::new_threshold(
                                    Some(optional_path.as_path()),
                                    StorageType::PUB,
                                    i,
                                )
                                .unwrap(),
                            ));
                        }
                    },
                    None => {
                        if overwrite {
                            FileStorage::purge_threshold(None, StorageType::PUB, i).unwrap();
                        }
                        pub_storages.push(StorageProxy::File(
                            FileStorage::new_threshold(None, StorageType::PUB, i).unwrap(),
                        ));
                    }
                }
            }
            let mut priv_storages = Vec::with_capacity(AMOUNT_PARTIES);
            for i in 1..=AMOUNT_PARTIES {
                match priv_url {
                    Some(ref url) => match url.scheme() {
                        "s3" => {
                            let blob_key_prefix = S3Storage::threshold_prefix(
                                Some(url.path().trim_start_matches('/').to_string()),
                                StorageType::PRIV,
                                i,
                            );
                            let mut storage = StorageProxy::S3(
                                S3Storage::new(
                                    aws_region.clone(),
                                    None,
                                    url.host_str().unwrap().to_string(),
                                    blob_key_prefix.clone(),
                                )
                                .await,
                            );
                            if overwrite {
                                let urls =
                                    storage.all_urls(blob_key_prefix.as_str()).await.unwrap();
                                for url in urls.values() {
                                    storage.delete_data(url).await.unwrap();
                                }
                            }
                            priv_storages.push(storage);
                        }
                        _ => {
                            let optional_path = url_to_pathbuf(url);
                            if overwrite {
                                FileStorage::purge_threshold(
                                    Some(optional_path.as_path()),
                                    StorageType::PRIV,
                                    i,
                                )
                                .unwrap();
                            }
                            priv_storages.push(StorageProxy::File(
                                FileStorage::new_threshold(
                                    Some(optional_path.as_path()),
                                    StorageType::PRIV,
                                    i,
                                )
                                .unwrap(),
                            ));
                        }
                    },
                    None => {
                        if overwrite {
                            FileStorage::purge_threshold(None, StorageType::PRIV, i).unwrap();
                        }
                        priv_storages.push(StorageProxy::File(
                            FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap(),
                        ));
                    }
                }
            }
            if show_existing {
                for i in 1..=AMOUNT_PARTIES {
                    show_keys(&pub_storages[i - 1], &priv_storages[i - 1]).await;
                }
                return;
            }
            ensure_threshold_keys_exist(
                &mut pub_storages,
                &mut priv_storages,
                &param_path,
                &DEFAULT_THRESHOLD_KEY_ID,
                deterministic,
            )
            .await;
            println!(
                "Default threshold keys written based on parameters stored in {}",
                param_path
            );
        }
    }
}

async fn show_keys<S>(pub_storage: &S, priv_storage: &S)
where
    S: Storage,
{
    for data_type in PubDataType::iter() {
        let data_type = data_type.to_string();
        let urlmap = pub_storage.all_urls(&data_type).await.unwrap();
        for (k, v) in urlmap {
            // TODO read the key material and print extra info
            let buf: Vec<u8> = pub_storage.read_data(&v).await.unwrap();
            println!("{data_type}, {k}, {v}, {}", buf.len());
        }
    }

    for data_type in PrivDataType::iter() {
        let data_type = data_type.to_string();
        let urlmap = priv_storage.all_urls(&data_type).await.unwrap();
        for (k, v) in urlmap {
            // TODO read the key material and print extra info
            let buf: Vec<u8> = pub_storage.read_data(&v).await.unwrap();
            println!("{data_type}, {k}, {v}, {}", buf.len());
        }
    }
}
