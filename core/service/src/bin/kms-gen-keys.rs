use anyhow::{Context, ensure};
use clap::Parser;
use core::fmt;
use futures_util::future::OptionFuture;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_lib::{
    conf::{
        AWSConfig, EnclaveBootstrapConfig, Keychain, Storage as StorageConfig, VaultConfig,
        init_conf, threshold::PeerConf,
    },
    consts::SIGNING_KEY_ID,
    cryptography::attestation::make_security_module,
    util::key_setup::{
        ensure_central_server_signing_keys_exist, ensure_threshold_server_signing_key_exists,
    },
    vault::{
        Vault,
        aws::build_aws_sdk_config,
        keychain::{awskms::build_aws_kms_client, make_keychain_proxy},
        storage::{Storage, StorageType, delete_at_request_id, make_storage, s3::build_s3_client},
    },
};
use observability::conf::TelemetryConfig;
use observability::telemetry::init_tracing;
use serde::{Deserialize, Serialize};
use std::{num::NonZeroUsize, sync::Arc};
use validator::Validate;

#[derive(Parser)]
#[clap(name = "Zama KMS Signing Key and Certificate Generator")]
#[clap(
    about = "A CLI tool for generating server signing keys and TLS certificates. \
    In centralized mode it produces a single signing key plus its verification material. \
    In threshold mode it produces the signing key and self-signed CA certificate for one party; \
    run it once per party in a multi-party deployment. \
    Pass --config-file to provide the key-generation settings.",
    after_long_help = r#"Config file example:

[keygen]
overwrite = false
show_existing = false

[public_vault.storage.file]
path = "./keys"

[private_vault.storage.file]
path = "./keys"

# Add this section to generate threshold signing material for one party.
[threshold]
my_id = 1
tls_subject = "kms-core-1""#
)]
struct Args {
    /// Read key-generation settings from a TOML config file.
    #[clap(long, short = 'f')]
    config_file: String,
}

#[derive(Clone, Debug, PartialEq)]
enum KeygenMode {
    Centralized,
    Threshold {
        signing_key_party_id: NonZeroUsize,
        tls_subject: String,
        tls_wildcard: bool,
    },
}

/// Full TOML configuration accepted by the kms-gen-keys binary.
#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct KmsGenKeysConfig {
    /// Required key-generation controls such as overwrite and listing behavior.
    #[validate(nested)]
    keygen: KeygenConfig,
    /// AWS settings used when any configured storage or keychain depends on AWS services.
    #[validate(nested)]
    aws: Option<AWSConfig>,
    /// Public vault where verification keys, verification addresses, and CA certificates are stored.
    #[validate(nested)]
    public_vault: Option<VaultConfig>,
    /// Private vault where server signing keys are stored.
    #[validate(nested)]
    private_vault: Option<VaultConfig>,
    /// Backup vault settings accepted for consistency with server configs but unused by key generation.
    #[validate(nested)]
    backup_vault: Option<VaultConfig>,
    /// Threshold-party settings; when absent, centralized signing material is generated.
    #[validate(nested)]
    threshold: Option<KeygenThresholdConfig>,
    /// Enclave bootstrap settings accepted for consistency with server configs but unused by key generation.
    #[validate(nested)]
    enclave_bootstrap: Option<EnclaveBootstrapConfig>,
    #[cfg(feature = "insecure")]
    /// Use the software-emulated enclave security module for local testing. Defaults to false.
    #[serde(default)]
    mock_enclave: bool,
}

/// Options under the required `[keygen]` section.
#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct KeygenConfig {
    #[cfg(any(test, feature = "testing", feature = "insecure"))]
    /// Generate deterministic test keys instead of fresh random keys. Defaults to false.
    #[serde(default)]
    deterministic: bool,
    /// Delete existing signing material at the fixed signing-key request ID before generation. Defaults to false.
    #[serde(default)]
    overwrite: bool,
    /// Print existing signing-material handles instead of generating or deleting keys. Defaults to false.
    #[serde(default)]
    show_existing: bool,
}

/// Optional `[threshold]` section used when generating one threshold party's signing material.
#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct KeygenThresholdConfig {
    /// One-indexed party id whose threshold signing material should be generated.
    #[validate(range(min = 1))]
    my_id: Option<usize>,
    /// TLS certificate subject for the generated self-signed CA certificate.
    #[validate(length(min = 1))]
    tls_subject: Option<String>,
    /// Generate a wildcard TLS certificate subject for the party. Defaults to false.
    #[serde(default)]
    tls_wildcard: bool,
    /// Peer list used to derive the TLS subject when `tls_subject` is not set.
    #[validate(nested)]
    peers: Option<Vec<PeerConf>>,
}

struct CentralCmdArgs<'a, PubS: Storage, PrivS: Storage> {
    pub_storage: &'a mut PubS,
    priv_storage: &'a mut PrivS,
    #[cfg(any(test, feature = "testing", feature = "insecure"))]
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
}

struct ThresholdCmdArgs<'a, PubS: Storage, PrivS: Storage> {
    pub_storage: &'a mut PubS,
    priv_storage: &'a mut PrivS,
    #[cfg(any(test, feature = "testing", feature = "insecure"))]
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    signing_key_party_id: NonZeroUsize,
    tls_subject: String,
    tls_wildcard: bool,
}

fn resolve_args(args: &Args) -> anyhow::Result<KmsGenKeysConfig> {
    let config = init_conf::<KmsGenKeysConfig>(&args.config_file).with_context(|| {
        format!(
            "failed to load kms-gen-keys config file {}; expected a [keygen] section",
            args.config_file
        )
    })?;
    config
        .validate()
        .context("invalid kms-gen-keys config file")?;
    Ok(config)
}

fn resolve_keygen_config_mode(
    threshold: Option<&KeygenThresholdConfig>,
) -> anyhow::Result<KeygenMode> {
    let Some(threshold) = threshold else {
        return Ok(KeygenMode::Centralized);
    };

    let my_id = threshold
        .my_id
        .context("threshold.my_id is required when generating threshold signing keys")?;
    let signing_key_party_id =
        NonZeroUsize::new(my_id).context("threshold.my_id must be non-zero")?;
    let tls_subject = resolve_threshold_tls_subject(
        threshold.tls_subject.as_deref(),
        threshold.peers.as_deref(),
        my_id,
    )?;

    Ok(KeygenMode::Threshold {
        signing_key_party_id,
        tls_subject,
        tls_wildcard: threshold.tls_wildcard,
    })
}

fn resolve_threshold_tls_subject(
    explicit_subject: Option<&str>,
    peers: Option<&[PeerConf]>,
    my_id: usize,
) -> anyhow::Result<String> {
    if let Some(subject) = explicit_subject
        .map(str::trim)
        .filter(|subject| !subject.is_empty())
    {
        return Ok(subject.to_string());
    }

    let peers = peers.context(
        "threshold.tls_subject is not set and threshold.peers is missing; cannot derive TLS subject",
    )?;
    let peer = peers.iter().find(|peer| peer.party_id == my_id).ok_or_else(|| {
        anyhow::anyhow!(
            "threshold.tls_subject is not set and threshold.peers has no entry for party {my_id}"
        )
    })?;
    let subject = peer
        .mpc_identity
        .as_deref()
        .map(str::trim)
        .filter(|identity| !identity.is_empty())
        .unwrap_or_else(|| peer.address.trim());
    ensure!(
        !subject.is_empty(),
        "cannot derive TLS subject for party {my_id} from an empty peer identity/address"
    );
    Ok(subject.to_string())
}

/// Generate the server signing keys and TLS material for a KMS deployment.
///
/// Two modes are supported:
/// - `centralized` produces a single signing key.
/// - `threshold` produces one party's signing key and self-signed CA certificate for mTLS.
///
/// Examples:
/// ```
/// cargo run --bin kms-gen-keys -- --config-file /path/to/kms-gen-keys.toml
/// cargo run --bin kms-gen-keys -- --help
/// ```
///
/// Minimal config file:
/// ```toml
/// [keygen]
/// overwrite = false
/// show_existing = false
///
/// [public_vault.storage.file]
/// path = "./keys"
///
/// [private_vault.storage.file]
/// path = "./keys"
///
/// # Add this section to generate threshold signing material for one party.
/// [threshold]
/// my_id = 1
/// tls_subject = "kms-core-1"
/// ```
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize telemetry with stdout tracing only and disabled metrics
    let telemetry = TelemetryConfig::builder()
        .tracing_service_name("kms_core".to_string())
        .build();
    init_tracing(&telemetry).await?;

    let config = resolve_args(&args)?;
    let mode = resolve_keygen_config_mode(config.threshold.as_ref())?;
    let public_storage = config
        .public_vault
        .as_ref()
        .map(|vault| vault.storage.clone());
    let private_vault = config.private_vault.as_ref();
    if private_vault.is_none() {
        tracing::warn!(
            "No [private_vault] section configured; kms-gen-keys will store private signing keys \
            in unencrypted filesystem storage using the default private storage path"
        );
    }
    let private_storage = private_vault.map(|vault| vault.storage.clone());
    let private_keychain_config = private_vault.and_then(|vault| vault.keychain.clone());

    // AWS S3 client
    let need_s3_client = public_storage.as_ref().is_some_and(StorageConfig::is_s_3)
        || private_storage.as_ref().is_some_and(StorageConfig::is_s_3);
    // AWS KMS client
    let need_awskms_client = private_keychain_config
        .as_ref()
        .is_some_and(Keychain::is_aws_kms);
    let aws_sdk_config = if need_s3_client || need_awskms_client || config.aws.is_some() {
        let aws = config
            .aws
            .as_ref()
            .context("[aws] config is required when using S3 storage or an AWS KMS keychain")?;
        Some(
            build_aws_sdk_config(
                aws.region.clone(),
                aws.imds_endpoint.clone(),
                aws.sts_endpoint.clone(),
            )
            .await,
        )
    } else {
        None
    };
    let s3_client = if need_s3_client {
        Some(
            build_s3_client(
                aws_sdk_config
                    .as_ref()
                    .expect("AWS config is built when S3 storage is configured"),
                config.aws.as_ref().and_then(|aws| aws.s3_endpoint.clone()),
            )
            .await?,
        )
    } else {
        None
    };
    let awskms_client = if need_awskms_client {
        Some(
            build_aws_kms_client(
                aws_sdk_config
                    .as_ref()
                    .expect("AWS config is built when AWS KMS keychain is configured"),
                config
                    .aws
                    .as_ref()
                    .and_then(|aws| aws.awskms_endpoint.clone()),
            )
            .await,
        )
    } else {
        None
    };
    // security module (used for remote attestation with AWS KMS only so far)
    let security_module = if need_awskms_client {
        Some(Arc::new(make_security_module(
            #[cfg(feature = "insecure")]
            config.mock_enclave,
        )?))
    } else {
        None
    };

    // create storages (one pub + one priv per invocation; multi-party
    // deployments invoke this binary once per party)
    let mut pub_storage = make_storage(public_storage, StorageType::PUB, s3_client.clone())?;
    let private_keychain = OptionFuture::from(private_keychain_config.as_ref().map(|k| {
        make_keychain_proxy(
            k,
            awskms_client.clone(),
            security_module.as_ref().map(Arc::clone),
            Some(&pub_storage),
            false,
        )
    }))
    .await
    .transpose()?;
    let mut priv_vault = Vault {
        storage: make_storage(private_storage, StorageType::PRIV, s3_client)?,
        keychain: private_keychain,
    };

    // generate keys
    match mode {
        KeygenMode::Centralized => {
            let mut cmdargs = CentralCmdArgs {
                pub_storage: &mut pub_storage,
                priv_storage: &mut priv_vault,
                #[cfg(any(test, feature = "testing", feature = "insecure"))]
                deterministic: config.keygen.deterministic,
                overwrite: config.keygen.overwrite,
                show_existing: config.keygen.show_existing,
            };
            handle_central_cmd(&mut cmdargs).await;
        }
        KeygenMode::Threshold {
            signing_key_party_id,
            tls_subject,
            tls_wildcard,
        } => {
            let mut cmdargs = ThresholdCmdArgs {
                pub_storage: &mut pub_storage,
                priv_storage: &mut priv_vault,
                #[cfg(any(test, feature = "testing", feature = "insecure"))]
                deterministic: config.keygen.deterministic,
                overwrite: config.keygen.overwrite,
                show_existing: config.keygen.show_existing,
                signing_key_party_id,
                tls_subject,
                tls_wildcard,
            };
            handle_threshold_cmd(&mut cmdargs).await;
        }
    }
    tracing::info!("Keygen finished successfully.");
    Ok(())
}

async fn handle_central_cmd<PubS: Storage, PrivS: Storage>(
    args: &mut CentralCmdArgs<'_, PubS, PrivS>,
) {
    process_signing_key_cmds(
        args.pub_storage,
        args.priv_storage,
        &SIGNING_KEY_ID,
        args.show_existing,
        args.overwrite,
    )
    .await;
    if !ensure_central_server_signing_keys_exist(
        args.pub_storage,
        args.priv_storage,
        &SIGNING_KEY_ID,
        #[cfg(any(test, feature = "testing", feature = "insecure"))]
        args.deterministic,
    )
    .await
    {
        tracing::warn!("Signing keys already exist, skipping generation");
    }
}

async fn handle_threshold_cmd<PubS: Storage, PrivS: Storage>(
    args: &mut ThresholdCmdArgs<'_, PubS, PrivS>,
) {
    process_signing_key_cmds(
        args.pub_storage,
        args.priv_storage,
        &SIGNING_KEY_ID,
        args.show_existing,
        args.overwrite,
    )
    .await;
    ensure_threshold_server_signing_key_exists(
        args.pub_storage,
        args.priv_storage,
        &SIGNING_KEY_ID,
        #[cfg(any(test, feature = "testing", feature = "insecure"))]
        args.deterministic,
        args.signing_key_party_id,
        args.tls_subject.clone(),
        args.tls_wildcard,
    )
    .await
    .expect("Could not access storage");
}

async fn process_signing_key_cmds<PubS: Storage, PrivS: Storage>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    req_id: &RequestId,
    show_existing: bool,
    overwrite: bool,
) {
    process_cmd(
        pub_storage,
        vec![
            &PubDataType::VerfKey,
            &PubDataType::VerfAddress,
            &PubDataType::CACert,
        ],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
    process_cmd(
        priv_storage,
        vec![&PrivDataType::SigningKey],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
}

async fn process_cmd<S: Storage, D: fmt::Display>(
    storage: &mut S,
    data_types: Vec<D>,
    req_id: &RequestId,
    show_existing: bool,
    overwrite: bool,
) {
    for dt in data_types {
        let data_type = &dt.to_string();
        if show_existing {
            show_key(storage, data_type).await;
            return;
        }
        if overwrite {
            tracing::info!(
                "Deleting {} under request ID {:} from storage \"{}\"...",
                data_type,
                &req_id.to_string(),
                storage.info()
            );
            // Ignore an error as it is likely because the data does not exist
            let _ = delete_at_request_id(storage, req_id, data_type).await;
        }
    }
}

async fn show_key<S: Storage>(storage: &S, data_type: &str) {
    let ids = storage.all_data_ids(data_type).await.unwrap();
    for id in ids {
        // TODO read the key material and print extra info
        let exists = storage.data_exists(&id, data_type).await.unwrap();
        println!("{data_type}, {id}, exists={exists}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_lib::conf::{
        AwsKmsKeySpec, AwsKmsKeychain, FileStorage as FileStorageConfig,
        S3Storage as S3StorageConfig,
    };
    use std::path::PathBuf;
    use url::Url;

    fn base_config() -> KmsGenKeysConfig {
        KmsGenKeysConfig {
            keygen: KeygenConfig {
                #[cfg(any(test, feature = "testing", feature = "insecure"))]
                deterministic: false,
                overwrite: false,
                show_existing: false,
            },
            aws: None,
            public_vault: None,
            private_vault: None,
            backup_vault: None,
            threshold: None,
            enclave_bootstrap: None,
            #[cfg(feature = "insecure")]
            mock_enclave: false,
        }
    }

    fn threshold_config(my_id: Option<usize>) -> KeygenThresholdConfig {
        KeygenThresholdConfig {
            my_id,
            tls_subject: None,
            tls_wildcard: false,
            peers: None,
        }
    }

    fn peer(party_id: usize, address: &str, mpc_identity: Option<&str>) -> PeerConf {
        PeerConf {
            party_id,
            address: address.to_string(),
            mpc_identity: mpc_identity.map(ToString::to_string),
            port: 50001,
            tls_cert: None,
            verification_address: None,
        }
    }

    fn resolve_mode_for_test(config: &KmsGenKeysConfig) -> anyhow::Result<KeygenMode> {
        resolve_keygen_config_mode(config.threshold.as_ref())
    }

    fn resolved_tls_subject(mode: KeygenMode) -> String {
        match mode {
            KeygenMode::Threshold { tls_subject, .. } => tls_subject,
            KeygenMode::Centralized => panic!("expected threshold mode"),
        }
    }

    #[test]
    fn config_file_resolves_centralized_defaults() {
        let config = base_config();
        let mode = resolve_mode_for_test(&config).unwrap();

        assert_eq!(mode, KeygenMode::Centralized);
        assert!(config.public_vault.is_none());
        assert!(config.private_vault.is_none());
        assert!(!config.keygen.overwrite);
        assert!(!config.keygen.show_existing);
        #[cfg(any(test, feature = "testing", feature = "insecure"))]
        assert!(!config.keygen.deterministic);
        #[cfg(feature = "insecure")]
        assert!(!config.mock_enclave);
    }

    #[test]
    fn keygen_flags_are_read_from_config() {
        let mut config = base_config();
        config.keygen = KeygenConfig {
            #[cfg(any(test, feature = "testing", feature = "insecure"))]
            deterministic: true,
            overwrite: true,
            show_existing: true,
        };

        #[cfg(any(test, feature = "testing", feature = "insecure"))]
        assert!(config.keygen.deterministic);
        assert!(config.keygen.overwrite);
        assert!(config.keygen.show_existing);
    }

    #[cfg(feature = "insecure")]
    #[test]
    fn mock_enclave_is_read_from_config() {
        let mut config = base_config();
        config.mock_enclave = true;

        assert!(config.mock_enclave);
    }

    #[cfg(feature = "insecure")]
    #[test]
    fn keygen_toml_deserializes_top_level_mock_enclave() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("kms-gen-keys.toml");
        std::fs::write(
            &config_path,
            r#"
mock_enclave = true

[keygen]
"#,
        )
        .unwrap();

        let config = init_conf::<KmsGenKeysConfig>(config_path.to_str().unwrap()).unwrap();

        assert!(config.mock_enclave);
    }

    #[test]
    fn threshold_tls_subject_prefers_explicit_config() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(2));
        threshold.tls_subject = Some(" explicit-party ".to_string());
        threshold.peers = Some(vec![peer(2, "peer-address", Some("peer-identity"))]);
        config.threshold = Some(threshold);

        let mode = resolve_mode_for_test(&config).unwrap();

        assert_eq!(resolved_tls_subject(mode), "explicit-party");
    }

    #[test]
    fn threshold_tls_subject_uses_matching_peer_identity() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(2));
        threshold.peers = Some(vec![
            peer(1, "party-one-address", Some("party-one")),
            peer(2, "party-two-address", Some("party-two")),
        ]);
        config.threshold = Some(threshold);

        let mode = resolve_mode_for_test(&config).unwrap();

        assert_eq!(resolved_tls_subject(mode), "party-two");
    }

    #[test]
    fn threshold_tls_subject_falls_back_to_peer_address() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(1));
        threshold.peers = Some(vec![peer(1, "party-one-address", Some("   "))]);
        config.threshold = Some(threshold);

        let mode = resolve_mode_for_test(&config).unwrap();

        assert_eq!(resolved_tls_subject(mode), "party-one-address");
    }

    #[test]
    fn threshold_config_requires_my_id() {
        let mut config = base_config();
        let mut threshold = threshold_config(None);
        threshold.tls_subject = Some("party-one".to_string());
        config.threshold = Some(threshold);

        let err = resolve_mode_for_test(&config).unwrap_err().to_string();

        assert!(err.contains("threshold.my_id"));
    }

    #[test]
    fn threshold_config_requires_matching_peer_when_subject_is_not_explicit() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(2));
        threshold.peers = Some(vec![peer(1, "party-one-address", None)]);
        config.threshold = Some(threshold);

        let err = resolve_mode_for_test(&config).unwrap_err().to_string();

        assert!(err.contains("no entry for party 2"));
    }

    #[test]
    fn config_file_preserves_aws_storage_and_keychain() {
        let mut config = base_config();
        config.aws = Some(AWSConfig {
            region: "us-east-1".to_string(),
            role_arn: Some("arn:aws:iam::123456789012:role/kms".to_string()),
            imds_endpoint: Some(Url::parse("http://127.0.0.1:5000").unwrap()),
            sts_endpoint: Some(Url::parse("http://127.0.0.1:4566").unwrap()),
            s3_endpoint: Some(Url::parse("http://127.0.0.1:4566").unwrap()),
            awskms_endpoint: Some(Url::parse("http://127.0.0.1:4566").unwrap()),
        });
        config.public_vault = Some(VaultConfig {
            storage: StorageConfig::S3(S3StorageConfig {
                bucket: "public-bucket".to_string(),
                prefix: Some("PUB-p1".to_string()),
            }),
            keychain: None,
        });
        config.private_vault = Some(VaultConfig {
            storage: StorageConfig::File(FileStorageConfig {
                path: PathBuf::from("/keys"),
                prefix: Some("PRIV-p1".to_string()),
            }),
            keychain: Some(Keychain::AwsKms(AwsKmsKeychain {
                root_key_id: "root-key".to_string(),
                root_key_spec: AwsKmsKeySpec::Symm,
            })),
        });

        assert_eq!(
            config.aws.as_ref().map(|aws| aws.region.as_str()),
            Some("us-east-1")
        );
        assert_eq!(
            config
                .public_vault
                .as_ref()
                .map(|vault| vault.storage.clone()),
            Some(StorageConfig::S3(S3StorageConfig {
                bucket: "public-bucket".to_string(),
                prefix: Some("PUB-p1".to_string()),
            }))
        );
        assert_eq!(
            config
                .private_vault
                .as_ref()
                .map(|vault| vault.storage.clone()),
            Some(StorageConfig::File(FileStorageConfig {
                path: PathBuf::from("/keys"),
                prefix: Some("PRIV-p1".to_string()),
            }))
        );
        assert_eq!(
            config
                .private_vault
                .as_ref()
                .and_then(|vault| vault.keychain.clone()),
            Some(Keychain::AwsKms(AwsKmsKeychain {
                root_key_id: "root-key".to_string(),
                root_key_spec: AwsKmsKeySpec::Symm,
            }))
        );
    }

    #[test]
    fn keygen_toml_deserializes_and_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("kms-gen-keys.toml");
        #[cfg(any(test, feature = "testing", feature = "insecure"))]
        let deterministic_config = "deterministic = true";
        #[cfg(not(any(test, feature = "testing", feature = "insecure")))]
        let deterministic_config = "";
        std::fs::write(
            &config_path,
            format!(
                r#"
[keygen]
{deterministic_config}
overwrite = true

[threshold]
my_id = 2
tls_subject = "kms-core-2"

[aws]
region = "eu-west-3"
s3_endpoint = "http://127.0.0.1:4566"
awskms_endpoint = "http://127.0.0.1:4566"

[public_vault.storage.s3]
bucket = "public-bucket"
prefix = "PUB-p2"

[private_vault.storage.s3]
bucket = "private-bucket"
prefix = "PRIV-p2"

[private_vault.keychain.aws_kms]
root_key_id = "root-key"
root_key_spec = "symm"
"#,
            ),
        )
        .unwrap();

        let config = init_conf::<KmsGenKeysConfig>(config_path.to_str().unwrap()).unwrap();
        config.validate().unwrap();
        let mode = resolve_mode_for_test(&config).unwrap();

        assert_eq!(resolved_tls_subject(mode), "kms-core-2");
        #[cfg(any(test, feature = "testing", feature = "insecure"))]
        assert!(config.keygen.deterministic);
        assert!(config.keygen.overwrite);
        assert_eq!(
            config
                .public_vault
                .as_ref()
                .map(|vault| vault.storage.clone()),
            Some(StorageConfig::S3(S3StorageConfig {
                bucket: "public-bucket".to_string(),
                prefix: Some("PUB-p2".to_string()),
            }))
        );
        assert_eq!(
            config
                .private_vault
                .as_ref()
                .map(|vault| vault.storage.clone()),
            Some(StorageConfig::S3(S3StorageConfig {
                bucket: "private-bucket".to_string(),
                prefix: Some("PRIV-p2".to_string()),
            }))
        );
    }
}
